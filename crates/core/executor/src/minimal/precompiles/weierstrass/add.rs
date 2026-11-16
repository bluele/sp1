use sp1_curves::{params::FieldParameters, EllipticCurve};
use sp1_jit::{Interrupt, SyscallContext};

/// Execute a weierstrass add assign syscall.
pub(crate) unsafe fn weierstrass_add_assign_syscall<E: EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    crate::minimal::precompiles::ec::ec_add::<E>(ctx, arg1, arg2, |p, q| {
        // The Weierstrass add chip inverts `q.x - p.x`, and the trace of its field operations is
        // generated for canonical coordinates.
        let modulus = E::BaseField::modulus();
        assert!(
            p.x != q.x && [&p.x, &p.y, &q.x, &q.y].into_iter().all(|c| *c < modulus),
            "Weierstrass add needs canonical coordinates and distinct x-coordinates"
        );
    })
    .map(|()| None)
}
