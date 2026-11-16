pub mod air;

pub use air::Poseidon2Chip;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use slop_algebra::PrimeField32;
    use sp1_core_executor::{add_halt, Instruction, Opcode, Program, Register, SyscallCode};
    use sp1_primitives::SP1Field;

    use crate::{
        io::SP1Stdin,
        utils::{run_test, setup_logger},
    };

    #[tokio::test]
    async fn test_poseidon2_largest_words() {
        setup_logger();

        const STATE: u64 = 0x10_0000;
        const P: u64 = SP1Field::ORDER_U32 as u64;

        let poseidon2 = SyscallCode::POSEIDON2 as u64;
        let mut instructions = Vec::new();
        // `P - 1` and `P - 2` reach the range check's cases of an equal and a smaller high limb.
        for (low, high) in [(P - 1, P - 2), (P - 2, P - 1)] {
            let word = low | (high << 32);
            instructions.push(Instruction::new(Opcode::ADDI, 29, 0, word, false, true));
            for i in 0..8 {
                instructions.push(Instruction::new(Opcode::SD, 29, 0, STATE + 8 * i, false, true));
            }
            instructions.extend([
                Instruction::new(Opcode::ADDI, Register::X5 as u8, 0, poseidon2, false, true),
                Instruction::new(Opcode::ADDI, Register::X10 as u8, 0, STATE, false, true),
                Instruction::new(
                    Opcode::ECALL,
                    Register::X5 as u8,
                    Register::X10 as u64,
                    Register::X11 as u64,
                    false,
                    false,
                ),
            ]);
        }
        add_halt(&mut instructions);

        run_test(Arc::new(Program::new(instructions, 0, 0)), SP1Stdin::new()).await.unwrap();
    }
}
