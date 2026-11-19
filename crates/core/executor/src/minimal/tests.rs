use std::sync::Arc;

use super::*;
use crate::{Program, SupervisorMode};

#[test]
fn test_chunk_stops_correctly() {
    use bincode::serialize;
    use sp1_jit::MinimalTrace;
    use test_artifacts::KECCAK256_ELF;

    let program = Program::from(&KECCAK256_ELF).unwrap();
    let program = Arc::new(program);

    let mut executor = MinimalExecutor::<SupervisorMode>::new(program.clone(), true, Some(10));
    executor.with_input(&serialize(&5_usize).unwrap());
    for i in 0..5 {
        executor.with_input(&serialize(&vec![i; i]).unwrap());
    }

    let mut lask_clk = 1;
    let mut last_pc = program.pc_start_abs;
    let mut last_registers = executor.registers();
    let mut chunk_count = 0;
    while let Some(chunk) = executor.execute_chunk() {
        assert_eq!(chunk.clk_start(), lask_clk, "chunk {chunk_count} clk_start mismatch");
        assert_eq!(chunk.pc_start(), last_pc, "chunk {chunk_count} pc_start mismatch");
        assert_eq!(
            chunk.start_registers(),
            last_registers,
            "chunk {chunk_count} registers mismatch"
        );

        lask_clk = chunk.clk_end();
        last_pc = executor.pc();
        last_registers = executor.registers();
        chunk_count += 1;
    }

    assert!(chunk_count > 5, "no chunks were executed");
}

// The native executor's `extern "C"` handler turns a precompile's panic into an abort.
#[cfg(sp1_use_portable_executor)]
mod refusal_tests {
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::Arc,
    };

    use num::BigUint;
    use slop_algebra::PrimeField32;
    use sp1_curves::{
        edwards::ed25519::{Ed25519, Ed25519BaseField},
        params::FieldParameters,
        weierstrass::{
            bls12_381::Bls12381, bn254::Bn254, secp256k1::Secp256k1, secp256r1::Secp256r1,
        },
        AffinePoint, EllipticCurve,
    };
    use sp1_primitives::SP1Field;

    use super::MinimalExecutor;
    use crate::{
        add_halt, ExecutionError, Instruction, Opcode, Program, Register, SupervisorMode,
        SyscallCode,
    };

    fn run(code: SyscallCode, a0: &[u64], a1: &[u64]) {
        const A0: u64 = 0x10_0000;
        const A1: u64 = 0x10_0100;

        let li = |register: u8, value: u64| {
            Instruction::new(Opcode::ADDI, register, 0, value, false, true)
        };
        let mut instructions = Vec::new();
        for (addr, words) in [(A0, a0), (A1, a1)] {
            for (i, &word) in words.iter().enumerate() {
                let addr = addr + 8 * i as u64;
                instructions.push(li(29, word));
                instructions.push(Instruction::new(Opcode::SD, 29, 0, addr, false, true));
            }
        }
        instructions.push(li(Register::X5 as u8, code as u64));
        instructions.push(li(Register::X10 as u8, A0));
        if !a1.is_empty() {
            // Poseidon2 takes one operand, and its chip requires the other argument to be zero.
            instructions.push(li(Register::X11 as u8, A1));
        }
        instructions.push(Instruction::new(
            Opcode::ECALL,
            Register::X5 as u8,
            Register::X10 as u64,
            Register::X11 as u64,
            false,
            false,
        ));
        add_halt(&mut instructions);

        let program = Arc::new(Program::new(instructions, 0, 0));
        let mut executor = MinimalExecutor::<SupervisorMode>::new(program, false, None);
        while executor.execute_chunk().is_some() {}
    }

    fn assert_refused(call: impl FnOnce(), message: &str) {
        let panic = catch_unwind(AssertUnwindSafe(call)).expect_err("the executor ran the call");
        // A different panic of the precompile, such as a debug assertion, is not the refusal.
        let found = panic.downcast_ref::<&str>().copied().unwrap_or_default();
        assert!(found.contains(message), "{found}");
    }

    #[test]
    fn test_poseidon2_refuses_a_word_at_the_modulus() {
        for index in 0..16 {
            let state = |word: u32| {
                let mut state = [0u64; 8];
                state[index / 2] = u64::from(word) << (32 * (index % 2));
                state
            };
            run(SyscallCode::POSEIDON2, &state(SP1Field::ORDER_U32 - 1), &[]);
            assert_refused(
                || run(SyscallCode::POSEIDON2, &state(SP1Field::ORDER_U32), &[]),
                "not a canonical field element",
            );
        }
    }

    fn weierstrass_add_refusals<E: EllipticCurve>(code: SyscallCode) {
        let add = |p: &AffinePoint<E>, q: &AffinePoint<E>| {
            run(code, &p.to_words_le(), &q.to_words_le());
        };
        let refused = |p: &AffinePoint<E>, q: &AffinePoint<E>| {
            assert_refused(|| add(p, q), "canonical coordinates and distinct x");
        };

        let modulus = E::BaseField::modulus();
        let g = E::ec_generator();
        let g2 = E::ec_double(&g);
        add(&g, &g2);

        refused(&g, &g);
        refused(&g, &E::ec_neg(&g));
        refused(&AffinePoint::new(modulus.clone(), g.y.clone()), &g2);
        refused(&AffinePoint::new(g.x.clone(), modulus.clone()), &g2);
        refused(&g, &AffinePoint::new(modulus.clone(), g2.y.clone()));
        refused(&g, &AffinePoint::new(g2.x.clone(), modulus));
    }

    #[test]
    fn test_weierstrass_add_refuses_equal_x_and_a_coordinate_at_the_modulus() {
        weierstrass_add_refusals::<Secp256k1>(SyscallCode::SECP256K1_ADD);
        weierstrass_add_refusals::<Secp256r1>(SyscallCode::SECP256R1_ADD);
        weierstrass_add_refusals::<Bn254>(SyscallCode::BN254_ADD);
        weierstrass_add_refusals::<Bls12381>(SyscallCode::BLS12381_ADD);
    }

    fn weierstrass_double_refusals<E: EllipticCurve>(code: SyscallCode) {
        let double = |p: &AffinePoint<E>| run(code, &p.to_words_le(), &[]);
        let refused = |p: &AffinePoint<E>| {
            assert_refused(|| double(p), "canonical coordinates and a non-zero y");
        };

        let modulus = E::BaseField::modulus();
        let g = E::ec_generator();
        double(&g);

        refused(&AffinePoint::new(g.x.clone(), BigUint::ZERO));
        refused(&AffinePoint::new(modulus.clone(), g.y.clone()));
        refused(&AffinePoint::new(g.x.clone(), modulus));
    }

    #[test]
    fn test_weierstrass_double_refuses_a_zero_y_and_a_coordinate_at_the_modulus() {
        weierstrass_double_refusals::<Secp256k1>(SyscallCode::SECP256K1_DOUBLE);
        weierstrass_double_refusals::<Secp256r1>(SyscallCode::SECP256R1_DOUBLE);
        weierstrass_double_refusals::<Bn254>(SyscallCode::BN254_DOUBLE);
        weierstrass_double_refusals::<Bls12381>(SyscallCode::BLS12381_DOUBLE);
    }

    #[test]
    fn test_edwards_add_refuses_a_point_off_the_curve_or_non_canonical() {
        let add = |p: &AffinePoint<Ed25519>, q: &AffinePoint<Ed25519>| {
            run(SyscallCode::ED_ADD, &p.to_words_le(), &q.to_words_le());
        };

        let modulus = Ed25519BaseField::modulus();
        let g = Ed25519::ec_generator();
        let g2 = Ed25519::ec_double(&g);
        add(&g, &g2);

        for bad in [
            // Keeps `y` and the sign of `x`, from which the addition rebuilds its operand.
            AffinePoint::new(&g.x + 2u32, g.y.clone()),
            AffinePoint::new(&g.x + &modulus, g.y.clone()),
            AffinePoint::new(BigUint::ZERO, &modulus + 1u32),
        ] {
            assert_refused(|| add(&bad, &g2), "canonical points on the curve");
            assert_refused(|| add(&g2, &bad), "canonical points on the curve");
            assert_refused(|| add(&bad, &bad), "canonical points on the curve");
        }
    }

    #[test]
    fn test_edwards_decompress_refuses_a_non_canonical_y() {
        let decompress = |y: &BigUint| {
            let slice = AffinePoint::<Ed25519>::new(BigUint::ZERO, y.clone()).to_words_le();
            run(SyscallCode::ED_DECOMPRESS, &slice, &[]);
        };

        let g = Ed25519::ec_generator();
        decompress(&g.y);
        decompress(&(Ed25519BaseField::modulus() - 1u32));

        for y in [
            Ed25519BaseField::modulus(),
            // Clearing bit 255 would recover the generator's y.
            &g.y + (BigUint::from(1u32) << 255),
        ] {
            assert_refused(|| decompress(&y), "canonical y");
        }
    }

    #[test]
    fn test_uint256_mul_refuses_a_quotient_above_256_bits() {
        let words = |values: &[&BigUint]| -> Vec<u64> {
            values.iter().flat_map(|value| value.iter_u64_digits().chain([0; 4]).take(4)).collect()
        };
        let mulmod = |x: &BigUint, y: &BigUint, modulus: &BigUint| {
            run(SyscallCode::UINT256_MUL, &words(&[x]), &words(&[y, modulus]));
        };

        let max = (BigUint::from(1u32) << 256) - 1u32;
        // The quotient of `max * max` by `max` is the largest that fits, and by `max - 1` it is
        // 2^256.
        mulmod(&max, &max, &max);
        // A zero modulus stands for 2^256.
        mulmod(&max, &max, &BigUint::ZERO);
        // Both operands and the quotient may exceed the modulus.
        mulmod(&BigUint::from(5u32), &BigUint::from(7u32), &BigUint::from(3u32));

        assert_refused(|| mulmod(&max, &max, &(&max - 1u32)), "quotient");
    }

    /// Run `instructions` and halt, under a memory limit as a caller that bounds memory runs a
    /// program, with `input` in the hint stream.
    fn try_run(mut instructions: Vec<Instruction>, input: &[u8]) -> Result<(), ExecutionError> {
        add_halt(&mut instructions);
        let program = Arc::new(Program::new(instructions, 0, 0));
        let mut executor =
            MinimalExecutor::<SupervisorMode>::new_with_limit(program, false, None, Some(1 << 30));
        executor.with_input(input);
        while executor.try_execute_chunk()?.is_some() {}
        Ok(())
    }

    #[test]
    fn test_an_access_below_the_stack_guard_is_refused() {
        const GUARD: u64 = 1 << 16;
        let li = |register: Register, value: u64| {
            Instruction::new(Opcode::ADDI, register as u8, 0, value, false, true)
        };
        let ecall = |code: SyscallCode, args: &[u64]| {
            let mut instructions = vec![li(Register::X5, code as u64)];
            for (&register, &arg) in [Register::X10, Register::X11, Register::X12].iter().zip(args)
            {
                instructions.push(li(register, arg));
            }
            instructions.push(Instruction::new(
                Opcode::ECALL,
                Register::X5 as u8,
                Register::X10 as u64,
                Register::X11 as u64,
                false,
                false,
            ));
            instructions
        };
        let store = |addr| {
            vec![li(Register::X29, 7), Instruction::new(Opcode::SD, 29, 0, addr, false, true)]
        };
        let load = |addr| vec![Instruction::new(Opcode::LD, 29, 0, addr, false, true)];
        let poseidon2 = |addr| ecall(SyscallCode::POSEIDON2, &[addr]);
        let hint = |addr| ecall(SyscallCode::HINT_READ, &[addr, 8]);

        for addr in [GUARD, GUARD + 8] {
            try_run(store(addr), &[]).unwrap();
            try_run(load(addr), &[]).unwrap();
            try_run(poseidon2(addr), &[]).unwrap();
            try_run(hint(addr), &[1; 8]).unwrap();
        }
        for addr in [0, 8, GUARD - 8] {
            for (case, input) in [
                (store(addr), &[][..]),
                (load(addr), &[][..]),
                (poseidon2(addr), &[][..]),
                (hint(addr), &[1u8; 8][..]),
            ] {
                assert!(
                    matches!(
                        try_run(case, input),
                        Err(ExecutionError::InvalidMemoryAccess(_, refused)) if refused == addr
                    ),
                    "{addr:#x}"
                );
            }
        }
        // The circuit's `WRITE` reads no memory, and an empty buffer may point anywhere: the
        // executor reads the word at its pointer without a trace, and runs it.
        try_run(ecall(SyscallCode::WRITE, &[1, 1, 0]), &[]).unwrap();
    }
}

/// Differential tests comparing the portable executor against the native `x86_64` executor.
/// Only compiled on `x86_64` with the profiling feature enabled.
#[cfg(all(target_arch = "x86_64", feature = "profiling"))]
mod differential_tests {
    use std::sync::Arc;

    use crate::{
        debug::compare_states, minimal::arch::x86_64::MinimalExecutor as NativeExecutor, Program,
        SupervisorMode,
    };
    use sp1_jit::debug::DebugState;
    use sp1_primitives::Elf;

    use super::MinimalExecutor;

    #[allow(clippy::cast_precision_loss)]
    fn run_program_and_compare_end_state(program: &Elf) {
        let program = Program::from(program).unwrap();
        let program = Arc::new(program);

        // Run the native x86_64 executor
        let mut native_executor =
            NativeExecutor::<SupervisorMode>::new(program.clone(), false, None);
        let native_time = {
            let start = std::time::Instant::now();
            while native_executor.execute_chunk().is_some() {}
            start.elapsed()
        };

        // Run the portable executor
        let mut portable_executor =
            MinimalExecutor::<SupervisorMode>::new(program.clone(), false, None);
        let portable_time = {
            let start = std::time::Instant::now();
            while portable_executor.execute_chunk().is_some() {}
            start.elapsed()
        };

        // Report performance
        let cycles = portable_executor.global_clk();
        let portable_mhz = cycles as f64 / (portable_time.as_micros() as f64);
        eprintln!("cycles={cycles}");
        eprintln!("Portable executor MHz={portable_mhz} MHz");

        let native_cycles = native_executor.global_clk();
        let native_mhz = native_cycles as f64 / (native_time.as_micros() as f64);
        eprintln!("Native executor MHz={native_mhz} MHz");

        // Compare states
        let (is_equal, report) = compare_states(
            &program,
            &portable_executor.current_state(),
            &native_executor.current_state(),
        );
        assert!(is_equal, "state mismatch:\n{report}");
    }

    #[test]
    fn test_run_keccak_with_input() {
        use bincode::serialize;
        use test_artifacts::KECCAK256_ELF;

        let program = Program::from(&KECCAK256_ELF).unwrap();
        let program = Arc::new(program);

        // Run the portable executor
        let mut portable_executor =
            MinimalExecutor::<SupervisorMode>::new(program.clone(), false, None);
        portable_executor.with_input(&serialize(&5_usize).unwrap());
        for i in 0..5 {
            portable_executor.with_input(&serialize(&vec![i; i]).unwrap());
        }
        while portable_executor.execute_chunk().is_some() {}

        // Run the native x86_64 executor
        let mut native_executor =
            NativeExecutor::<SupervisorMode>::new(program.clone(), false, None);
        native_executor.with_input(&serialize(&5_usize).unwrap());
        for i in 0..5 {
            native_executor.with_input(&serialize(&vec![i; i]).unwrap());
        }
        while native_executor.execute_chunk().is_some() {}

        let (is_equal, report) = compare_states(
            &program,
            &portable_executor.current_state(),
            &native_executor.current_state(),
        );
        assert!(is_equal, "state mismatch:\n{report}");
    }

    #[test]
    fn test_run_fibonacci() {
        run_program_and_compare_end_state(&test_artifacts::FIBONACCI_ELF);
    }

    #[test]
    fn test_run_sha256() {
        run_program_and_compare_end_state(&test_artifacts::SHA2_ELF);
    }

    #[test]
    fn test_run_sha_extend() {
        run_program_and_compare_end_state(&test_artifacts::SHA_EXTEND_ELF);
    }

    #[test]
    fn test_run_sha_compress() {
        run_program_and_compare_end_state(&test_artifacts::SHA_COMPRESS_ELF);
    }

    #[test]
    fn test_run_keccak_permute() {
        run_program_and_compare_end_state(&test_artifacts::KECCAK_PERMUTE_ELF);
    }

    #[test]
    fn test_run_secp256k1_add() {
        run_program_and_compare_end_state(&test_artifacts::SECP256K1_ADD_ELF);
    }

    #[test]
    fn test_run_secp256k1_double() {
        run_program_and_compare_end_state(&test_artifacts::SECP256K1_DOUBLE_ELF);
    }

    #[test]
    fn test_run_secp256r1_add() {
        run_program_and_compare_end_state(&test_artifacts::SECP256R1_ADD_ELF);
    }

    #[test]
    fn test_run_secp256r1_double() {
        run_program_and_compare_end_state(&test_artifacts::SECP256R1_DOUBLE_ELF);
    }

    #[test]
    fn test_run_bls12_381_add() {
        run_program_and_compare_end_state(&test_artifacts::BLS12381_ADD_ELF);
    }

    #[test]
    fn test_ed_add() {
        run_program_and_compare_end_state(&test_artifacts::ED_ADD_ELF);
    }

    #[test]
    fn test_bn254_add() {
        run_program_and_compare_end_state(&test_artifacts::BN254_ADD_ELF);
    }

    #[test]
    fn test_bn254_double() {
        run_program_and_compare_end_state(&test_artifacts::BN254_DOUBLE_ELF);
    }

    #[test]
    fn test_bn254_mul() {
        run_program_and_compare_end_state(&test_artifacts::BN254_MUL_ELF);
    }

    #[test]
    fn test_uint256_mul() {
        run_program_and_compare_end_state(&test_artifacts::UINT256_MUL_ELF);
    }

    #[test]
    fn test_bls12_381_fp() {
        run_program_and_compare_end_state(&test_artifacts::BLS12381_FP_ELF);
    }

    #[test]
    fn test_bls12_381_fp2_mul() {
        run_program_and_compare_end_state(&test_artifacts::BLS12381_FP2_MUL_ELF);
    }

    #[test]
    fn test_bls12_381_fp2_addsub() {
        run_program_and_compare_end_state(&test_artifacts::BLS12381_FP2_ADDSUB_ELF);
    }

    #[test]
    fn test_bn254_fp() {
        run_program_and_compare_end_state(&test_artifacts::BN254_FP_ELF);
    }

    #[test]
    fn test_bn254_fp2_addsub() {
        run_program_and_compare_end_state(&test_artifacts::BN254_FP2_ADDSUB_ELF);
    }

    #[test]
    fn test_bn254_fp2_mul() {
        run_program_and_compare_end_state(&test_artifacts::BN254_FP2_MUL_ELF);
    }

    #[test]
    fn test_ed_decompress() {
        run_program_and_compare_end_state(&test_artifacts::ED_DECOMPRESS_ELF);
    }

    #[test]
    fn test_ed25519_verify() {
        run_program_and_compare_end_state(&test_artifacts::ED25519_ELF);
    }

    #[test]
    fn test_ssz_withdrawls() {
        run_program_and_compare_end_state(&test_artifacts::SSZ_WITHDRAWALS_ELF);
    }

    #[test]
    #[ignore = "Expensive test that is very useful for debugging"]
    fn test_compare_registers_at_each_timestamp() {
        use crate::debug::render_current_instruction;
        use sp1_jit::debug;
        use std::fmt::Write;

        const ELF: Elf = test_artifacts::ED25519_ELF;

        let program = Program::from(&ELF).unwrap();
        let program = Arc::new(program);

        std::thread::scope(|s| {
            // Portable executor (MinimalExecutor when profiling is enabled)
            let mut portable =
                MinimalExecutor::<SupervisorMode>::new(program.clone(), true, Some(50));
            let portable_rx =
                portable.new_debug_receiver().expect("Failed to create debug receiver");

            // Native x86_64 executor
            let mut native = NativeExecutor::<SupervisorMode>::new(program.clone(), true, None);
            let native_rx = native.new_debug_receiver().expect("Failed to create debug receiver");

            s.spawn(move || while portable.execute_chunk().is_some() {});
            s.spawn(move || while native.execute_chunk().is_some() {});
            s.spawn(move || {
                let mut got_prev: Option<debug::State> = None;
                let mut expected_prev: Option<debug::State> = None;

                for (cycle, (portable_msg, native_msg)) in
                    portable_rx.into_iter().zip(native_rx).enumerate()
                {
                    let (portable_msg, native_msg) = match (portable_msg, native_msg) {
                        (Some(portable), Some(native)) => (portable, native),
                        (Some(_), None) => {
                            eprintln!("portable={portable_msg:?}");
                            eprintln!("native=  {native_msg:?}");
                            panic!("Portable executor finished, but native executor did not");
                        }
                        (None, Some(_)) => {
                            eprintln!("portable={portable_msg:?}");
                            eprintln!("native=  {native_msg:?}");
                            panic!("Native executor finished, but portable executor did not");
                        }
                        (None, None) => break,
                    };

                    let (is_equal, mut report) =
                        compare_states(&program, &portable_msg, &native_msg);
                    if let (Some(got), Some(expected)) = (got_prev, expected_prev) {
                        let got = render_current_instruction(&program, &got);
                        let expected = render_current_instruction(&program, &expected);
                        writeln!(report).unwrap();
                        writeln!(report, "PREVIOUS INSTRUCTION").unwrap();
                        writeln!(report, "       GOT: {got}").unwrap();
                        writeln!(report, "  EXPECTED: {expected}").unwrap();
                    }
                    if is_equal {
                        eprintln!("state matches at cycle {cycle}");
                    } else {
                        eprintln!("{report}");
                        panic!("state mismatch at cycle {cycle}");
                    }
                    got_prev = Some(portable_msg);
                    expected_prev = Some(native_msg);
                }
            });
        });
    }
}
