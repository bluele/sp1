use num::BigUint;
use sp1_curves::{edwards::EdwardsParameters, params::FieldParameters, AffinePoint, EllipticCurve};
use sp1_jit::{Interrupt, SyscallContext};

pub unsafe fn edwards_add<E: EdwardsParameters + EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    crate::minimal::precompiles::ec::ec_add::<E>(ctx, arg1, arg2, |p, q| {
        // The Edwards add chip adds the coordinates as given, and the executor the point that it
        // rebuilds from `y` and the sign of `x`: the same for a canonical point on the curve.
        let modulus = E::BaseField::modulus();
        let d = BigUint::from_bytes_le(&E::D);
        let on_curve = |point: &AffinePoint<E>| {
            let xx = &point.x * &point.x % &modulus;
            let yy = &point.y * &point.y % &modulus;
            point.x < modulus
                && point.y < modulus
                && yy == (&xx + &d * (&xx * &yy % &modulus) + 1u32) % &modulus
        };
        // A guest doubles a point by passing it twice.
        assert!(
            on_curve(p) && ((p.x == q.x && p.y == q.y) || on_curve(q)),
            "Edwards add needs canonical points on the curve"
        );
    })
    .map(|()| None)
}
