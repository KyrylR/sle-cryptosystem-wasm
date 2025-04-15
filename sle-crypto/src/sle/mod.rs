///#! A tiny “tss_modulo”‐style null‐space solver in Rust.
///#!
///#! Solves A·x ≡ 0 (mod m), returning a basis of at most n generators.
///#!
///#! Uses only `i64` arithmetic and extended‐gcd.
use crate::ring::{Matrix, Ring, Vector, extended_gcd, gcd};

/// Modular inverse of a mod m, if it exists.
pub fn modinv(a: i64, m: i64) -> Option<i64> {
    let (g, x, _) = extended_gcd(a, m);
    if g != 1 {
        None
    } else {
        // x·a ≡ 1 (mod m)
        Some((x % m + m) % m)
    }
}

/// Extended GCD over a slice of length n.
/// Returns (g, comb) with ∑ comb[i]·eq[i] = g.
pub fn ext_gcd_vec(eq: &[i64]) -> (i64, Vec<i64>) {
    let n = eq.len();
    // Find first non‐zero to seed
    let mut comb = vec![0; n];
    let mut g = 0;
    let mut idx = 0;
    for (i, &v) in eq.iter().enumerate() {
        if v != 0 {
            g = v;
            comb[i] = 1;
            idx = i;
            break;
        }
    }
    // If all zero => gcd = 0, but we treat as 1 with trivial comb
    if g == 0 {
        return (0, comb);
    }
    // Fold in each further coefficient
    for j in (idx + 1)..n {
        let v = eq[j];
        if v == 0 {
            continue;
        }
        let (g2, s, t) = extended_gcd(g, v);
        // New gcd is g2 = s*g + t*v
        // scale old comb by s, set comb[j]=t
        for c in comb[..j].iter_mut() {
            *c *= s;
        }
        comb[j] = t;
        g = g2;
    }
    (g.abs(), comb)
}

/// Normalize each entry of v mod m into [0..m).
#[inline]
pub fn normalize(v: &mut [i64], m: i64) {
    for x in v.iter_mut() {
        *x %= m;
        if *x < 0 {
            *x += m;
        }
    }
}

/// Test if two vectors are scalar multiples mod m.
pub fn are_dependent(u: &[i64], v: &[i64], m: i64) -> bool {
    let n = u.len();
    // find i with u[i] coprime to m
    for i in 0..n {
        let ui = u[i] % m;
        let vi = v[i] % m;
        if ui != 0 {
            if let Some(inv) = modinv(ui, m) {
                let k = (inv * vi) % m;
                return u
                    .iter()
                    .zip(v)
                    .all(|(&uu, &vv)| ((uu % m) * k - vv % m) % m == 0);
            }
        }
    }
    // fallback: both zero everywhere?
    u.iter().zip(v).all(|(&uu, &vv)| uu % m == 0 && vv % m == 0)
}

/// Prune scalar‐multiples in place.
pub fn prune_duplicates(vecs: &mut Vec<Vec<i64>>, m: i64) {
    let mut out: Vec<Vec<i64>> = Vec::with_capacity(vecs.len());
    for v in vecs.drain(..) {
        if !out.iter().any(|u| are_dependent(u, &v, m)) {
            out.push(v);
        }
    }
    *vecs = out;
}

/// Solve one equation e·x ≡ 0 (mod m), returning up to n basis vectors.
pub fn solve_one(eq: &[i64], m: i64) -> Vec<Vec<i64>> {
    let n = eq.len();
    // (A) If the equation is identically 0 mod m, it imposes no constraint:
    //     the null‐space is all of (Z/mZ)^n, so return the n standard unit vectors.
    if eq.iter().all(|&a| a.rem_euclid(m) == 0) {
        return (0..n)
            .map(|i| {
                let mut v = vec![0; n];
                v[i] = 1;
                v
            })
            .collect();
    }
    // find gcd and comb so ∑ comb[i]*eq[i] = g
    let (mut g, mut comb) = ext_gcd_vec(eq);
    // factor out gcd that also divides m
    let d = gcd(g, m);
    if d > 1 {
        g /= d;
        comb.iter_mut().for_each(|c| *c /= d);
    }
    // reduce modulus
    let mm = m / d.max(1);
    // normalize combination
    normalize(&mut comb, mm);

    // Build basis: for each i, take e_i = -eq[i]*comb + unit vector i
    let mut base = Vec::with_capacity(n);
    for i in 0..n {
        let mut v = vec![0; n];
        for j in 0..n {
            v[j] = (-eq[i] * comb[j]) % mm;
        }
        v[i] = (v[i] + 1) % mm;
        normalize(&mut v, mm);
        base.push(v);
    }
    base.retain(|v| v.iter().any(|&x| x.rem_euclid(mm) != 0));
    base
}

/// Solve the full system A·x ≡ 0 (mod m).
pub fn solve_system(a: &[Vec<i64>], m: i64) -> Vec<Vec<i64>> {
    let rows = a.len();
    if rows == 0 {
        return vec![];
    }
    // start with first equation
    let mut sol = solve_one(&a[0], m);
    // intersect with each further equation
    for r in 1..rows {
        let eq = &a[r];
        let k = sol.len();
        // build the projected "residual" vector L: for each basis vector s in sol,
        // compute eq·s (mod m)
        let mut L = Vec::with_capacity(k);
        for s in &sol {
            let sum = eq.iter().zip(s.iter()).map(|(&a, &b)| a * b).sum::<i64>() % m;
            L.push((sum + m) % m);
        }
        // solve L·y ≡ 0 to get new combos
        let new_combos = solve_one(&L, m);
        // build new basis by linearly combining old sol via each combo
        let mut new_sol = Vec::with_capacity(new_combos.len());
        for comb in new_combos {
            let mut v = vec![0; eq.len()];
            for (i, &c) in comb.iter().enumerate() {
                for j in 0..v.len() {
                    v[j] += c * sol[i][j];
                }
            }
            normalize(&mut v, m);
            new_sol.push(v);
        }
        prune_duplicates(&mut new_sol, m);
        sol = new_sol;
    }
    sol
}

/// Solve a single linear congruence
///     eq · x ≡ rhs   (mod m)
/// in n unknowns.
/// Returns `None` if inconsistent, else
/// `Some((x0, basis))` where
///  - `x0` is one particular solution (length n),
///  - `basis` spans all solutions of eq·x≡0 (mod m).
fn solve_one_inhomog(eq: &[i64], rhs: i64, m: i64) -> Option<(Vec<i64>, Vec<Vec<i64>>)> {
    let n = eq.len();

    // 1) Compute d0 = gcd(eq[0..], m)
    let (d0, _) = ext_gcd_vec(eq);
    let g0 = gcd(d0, m);
    // No solution unless g0 | rhs
    if rhs.rem_euclid(m) % g0 != 0 {
        return None;
    }

    // 2) Reduce modulus + RHS + coefficients by g0
    let m1 = m / g0;
    let rhs1 = (rhs.rem_euclid(m) / g0).rem_euclid(m1);
    let eq1: Vec<i64> = eq.iter().map(|&a| a / g0).collect();

    // 3) Compute comb so that ∑ comb[i]*eq1[i] = d1 = gcd(eq1)
    let (d1_raw, mut comb) = ext_gcd_vec(&eq1);
    let d1 = d1_raw.abs(); // d1 = d0/g0

    // 4) Invert d1 mod m1 (must exist because gcd(d1,m1)=1)
    let inv_d1 = modinv(d1, m1).expect("After dividing out g0, d1 and m1 must be coprime");

    // 5) Normalize comb mod m1, then scale by inv_d1 so that
    //    ∑ comb[i]*eq1[i] ≡ 1   (mod m1)
    normalize(&mut comb, m1);
    for c in comb.iter_mut() {
        *c = (*c * inv_d1).rem_euclid(m1);
    }

    // 6) Build one particular solution: x0[i] = comb[i]*rhs1 (mod m1)
    let mut x0 = vec![0; n];
    for i in 0..n {
        x0[i] = (comb[i].rem_euclid(m1) * rhs1).rem_euclid(m1);
    }

    // 7) Lift x0 back to modulo m
    for xi in x0.iter_mut() {
        *xi = xi.rem_euclid(m);
    }

    // 8) The homogeneous solution‐space is exactly what `solve_one(eq,m)` gives:
    let basis = solve_one(eq, m);

    Some((x0, basis))
}

fn verify(a: &[Vec<i64>], b: &[i64], m: i64, x: &[i64]) -> bool {
    for (row, &bi) in a.iter().zip(b.iter()) {
        let sum = row
            .iter()
            .zip(x.iter())
            .map(|(&ai, &xi)| (ai * xi).rem_euclid(m))
            .sum::<i64>()
            .rem_euclid(m);
        if sum != bi.rem_euclid(m) {
            return false;
        }
    }
    true
}

/// Solve the entire system A·x ≡ b (mod m).
/// - `a` is an m×n matrix (`Vec<Vec<i64>>`),
/// - `b` is length‐m RHS vector,
/// - `m` is the modulus.
///
/// Returns `None` if no solution; otherwise one particular `Vec<i64>` of length n.
pub fn solve_pr(a: &[Vec<i64>], b: &[i64], m: i64) -> Option<Vec<i64>> {
    let rows = a.len();
    if rows == 0 {
        return Some(Vec::new());
    }
    let cols = a[0].len();

    // 1) Solve the first equation inhomogeneously
    let (mut x0, mut basis) = solve_one_inhomog(&a[0], b[0], m)?;

    // If that already works for the full system, return it
    if verify(a, b, m, &x0) {
        return Some(x0);
    }

    // 2) Intersect with the remaining equations, one by one
    for i in 1..rows {
        let row = &a[i];
        let bi = b[i].rem_euclid(m);

        // compute current residual r0 = row·x0 mod m
        let r0: i64 = row
            .iter()
            .zip(x0.iter())
            .map(|(&ri, &xi)| (ri * xi).rem_euclid(m))
            .sum::<i64>()
            .rem_euclid(m);

        let need = (bi + m - r0).rem_euclid(m);

        // no homogeneous directions → just check consistency
        if basis.is_empty() {
            if need != 0 {
                // inconsistent
                return None;
            }
            continue;
        }

        // form L_j = row·basis[j] (mod m)
        let k = basis.len();
        let mut L = Vec::with_capacity(k);
        for h in &basis {
            let s: i64 = row
                .iter()
                .zip(h.iter())
                .map(|(&ri, &hi)| (ri * hi).rem_euclid(m))
                .sum::<i64>()
                .rem_euclid(m);
            L.push(s);
        }

        // solve L·α ≡ need  (mod m)
        let (alpha, new_null) = solve_one_inhomog(&L, need, m)?;

        // update x0 ← x0 + ∑ α[j]*basis[j]
        for j in 0..k {
            let coeff = alpha[j].rem_euclid(m);
            if coeff != 0 {
                for c in 0..cols {
                    x0[c] = (x0[c] + coeff * basis[j][c].rem_euclid(m)).rem_euclid(m);
                }
            }
        }

        // if this x0 now solves the *entire* system, return immediately
        if verify(a, b, m, &x0) {
            return Some(x0);
        }

        // rebuild the homogeneous basis
        let mut next = Vec::with_capacity(new_null.len());
        for comb in new_null {
            let mut v = vec![0; cols];
            for j in 0..comb.len() {
                let w = comb[j].rem_euclid(m);
                if w != 0 {
                    for c in 0..cols {
                        v[c] = (v[c] + w * basis[j][c].rem_euclid(m)).rem_euclid(m);
                    }
                }
            }
            next.push(v);
        }
        prune_duplicates(&mut next, m);
        basis = next;
    }

    // 3) After processing all rows, one final verify of x0
    if verify(a, b, m, &x0) {
        return Some(x0);
    }

    // 4) If that still failed, try x0 + h for each homogeneous direction h
    for h in &basis {
        let candidate: Vec<i64> = x0
            .iter()
            .zip(h.iter())
            .map(|(&x, &hh)| (x + hh).rem_euclid(m))
            .collect();
        if verify(a, b, m, &candidate) {
            return Some(candidate);
        }
    }

    // 5) No solution found
    None
}

pub fn solve(a: &Matrix, b: &Vector, ring: &Ring) -> Option<Vector> {
    solve_pr(a, b, ring.modulus as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sle() {
        let a: Matrix = vec![vec![2, 4, 7, 20], vec![0, 1, 11, 17]];
        let b: Vector = vec![16, 0];
        let ring = Ring::try_with(25).unwrap();

        let AT: Matrix = (0..4).map(|j| (0..2).map(|i| a[i][j]).collect()).collect();

        dbg!(solve_system(&a, ring.modulus as i64));
        dbg!(solve_system(&AT, ring.modulus as i64));

        dbg!(solve(&a, &b, &ring));
    }
}
