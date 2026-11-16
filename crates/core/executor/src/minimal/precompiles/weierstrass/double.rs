use num::Zero;
use sp1_curves::{params::FieldParameters, EllipticCurve};
use sp1_jit::{Interrupt, SyscallContext};

/// Execute a weierstrass double assign syscall.
pub(crate) unsafe fn weierstrass_double_assign_syscall<E: EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    crate::minimal::precompiles::ec::ec_double::<E>(ctx, arg1, arg2, |p| {
        // Trace generation divides by `2 * p.y`, and a non-canonical coordinate can make it fail or
        // produce a trace that does not verify.
        let modulus = E::BaseField::modulus();
        assert!(
            !p.y.is_zero() && p.x < modulus && p.y < modulus,
            "Weierstrass double needs canonical coordinates and a non-zero y-coordinate"
        );
    })
    .map(|()| None)
}
