use crate::errors::SLECryptoError;
use crate::ring::{Matrix, Ring, Vector};
use crate::sle::solve;

/// A·x where A is an m×n matrix and x is a length–n vector.
/// Returns an m‐vector.
pub fn matrix_vector_mul(a: &Matrix, x: &Vector, ring: &Ring) -> Result<Vector, SLECryptoError> {
    let m = a.len();
    if m == 0 {
        return Ok(Vec::new());
    }
    let n = a[0].len();
    if x.len() != n {
        return Err(SLECryptoError::DimensionMismatch(format!(
            "Matrix columns ({}) must match vector length ({})",
            n,
            x.len()
        )));
    }

    let mut y = vec![0i64; m];
    for i in 0..m {
        if a[i].len() != n {
            return Err(SLECryptoError::DimensionMismatch(format!(
                "Row {} has length {} but expected {}",
                i,
                a[i].len(),
                n
            )));
        }
        let mut sum = 0i64;
        for j in 0..n {
            let term = ring.mul(a[i][j], x[j]);
            sum = ring.add(sum, term);
        }
        y[i] = sum;
    }
    Ok(y)
}

/// x·A where x is a length–m row‐vector and A is m×n.  
/// Returns a length–n row‐vector.
pub fn vector_matrix_mul(x: &Vector, a: &Matrix, ring: &Ring) -> Result<Vector, SLECryptoError> {
    let m = x.len();
    if m == 0 {
        return Ok(Vec::new());
    }
    if a.len() != m {
        return Err(SLECryptoError::DimensionMismatch(format!(
            "Vector length ({}) must match matrix rows ({})",
            m,
            a.len()
        )));
    }
    let n = a[0].len();
    // sanity‐check ragged rows
    for (i, row) in a.iter().enumerate() {
        if row.len() != n {
            return Err(SLECryptoError::DimensionMismatch(format!(
                "Row {} has length {} but expected {}",
                i,
                row.len(),
                n
            )));
        }
    }

    let mut y = vec![0i64; n];
    for j in 0..n {
        let mut sum = 0i64;
        for i in 0..m {
            let term = ring.mul(x[i], a[i][j]);
            sum = ring.add(sum, term);
        }
        y[j] = sum;
    }
    Ok(y)
}

/// Computes the vector sum `c = a + b` modulo `m`, where `m` is the modulus of the ring.
///
/// # Errors
///
/// Returns `SLECryptoError::DimensionMismatch` if the vectors have different lengths.
pub fn vector_add(a: &Vector, b: &Vector, ring: &Ring) -> Result<Vector, SLECryptoError> {
    if a.len() != b.len() {
        return Err(SLECryptoError::DimensionMismatch(format!(
            "Vector lengths must match for addition ({} vs {})",
            a.len(),
            b.len()
        )));
    }
    let n = a.len();
    let mut c = vec![0; n];
    for i in 0..n {
        c[i] = ring.add(a[i], b[i]);
    }
    Ok(c)
}

/// Computes the vector difference `c = a - b` modulo `m`, where `m` is the modulus of the ring.
///
/// # Errors
///
/// Returns `SLECryptoError::DimensionMismatch` if the vectors have different lengths.
pub fn vector_sub(a: &Vector, b: &Vector, ring: &Ring) -> Result<Vector, SLECryptoError> {
    if a.len() != b.len() {
        return Err(SLECryptoError::DimensionMismatch(format!(
            "Vector lengths must match for subtraction ({} vs {})",
            a.len(),
            b.len()
        )));
    }
    let n = a.len();
    let mut c = vec![0; n];
    for i in 0..n {
        c[i] = ring.sub(a[i], b[i]);
    }
    Ok(c)
}

/// Computes the matrix product `C = AB` modulo `m`, where `m` is the modulus of the ring.
///
/// # Errors
///
/// Returns `SLECryptoError::DimensionMismatch` if the inner dimensions of the matrices do not match
/// or if rows within the matrices have inconsistent lengths.
pub fn matrix_mul(a: &Matrix, b: &Matrix, ring: &Ring) -> Result<Matrix, SLECryptoError> {
    let n = a.len(); // rows in A
    if n == 0 {
        return Ok(Matrix::new());
    }
    let p = b[0].len(); // cols in B
    let m_common = a[0].len(); // cols in A

    if b.len() != m_common {
        return Err(SLECryptoError::DimensionMismatch(format!(
            "Inner dimensions must match for matrix multiplication ({} vs {})",
            m_common,
            b.len()
        )));
    }

    let mut c = vec![vec![0; p]; n];

    for i in 0..n {
        if a[i].len() != m_common {
            return Err(SLECryptoError::DimensionMismatch(format!(
                "Matrix A row {} has incorrect length (expected {})",
                i, m_common
            )));
        }
        for j in 0..p {
            let mut sum = 0i64;
            #[allow(clippy::needless_range_loop)]
            for k in 0..m_common {
                if b[k].len() != p {
                    return Err(SLECryptoError::DimensionMismatch(format!(
                        "Matrix B row {} has incorrect length (expected {})",
                        k, p
                    )));
                }
                let term = ring.mul(a[i][k], b[k][j]);
                sum = ring.add(sum, term);
            }
            c[i][j] = sum;
        }
    }
    Ok(c)
}

/// Creates an identity matrix of size `n`.
pub fn identity_matrix(n: usize) -> Matrix {
    let mut identity = vec![vec![0; n]; n];
    #[allow(clippy::needless_range_loop)]
    for i in 0..n {
        identity[i][i] = 1;
    }
    identity
}

/// Calculates the rank of a matrix modulo `m`, the modulus defined by the `ring`.
///
/// The rank is the number of linearly independent rows (or columns).
/// This implementation uses Gaussian elimination over the ring.
///
/// # Errors
///
/// Returns `SLECryptoError::DimensionMismatch` if the matrix rows have inconsistent lengths.
/// Returns `SLECryptoError::InternalError` for internal calculation issues like GCD being zero.
pub fn matrix_rank(matrix: &Matrix, ring: &Ring) -> Result<usize, SLECryptoError> {
    let n = matrix.len(); // Number of rows
    if n == 0 {
        return Ok(0);
    }
    let m_vars = matrix[0].len(); // Number of columns
    if m_vars == 0 {
        return Ok(0);
    }

    // Create a mutable copy of the matrix and normalize
    let mut mat = matrix.clone();
    for row in mat.iter_mut() {
        if row.len() != m_vars {
            return Err(SLECryptoError::DimensionMismatch(format!(
                "Matrix row has incorrect length (expected {})",
                m_vars
            )));
        }
        for val in row.iter_mut() {
            *val = ring.normalize(*val);
        }
    }

    let mut rank = 0;
    let mut pivot_row = 0;

    for col in 0..m_vars {
        // Iterate through columns
        if pivot_row >= n {
            // All rows processed
            break;
        }

        // Find pivot row for this column
        let mut pivot_idx = pivot_row;
        while pivot_idx < n && mat[pivot_idx][col] == 0 {
            pivot_idx += 1;
        }

        if pivot_idx < n {
            // Pivot found at (pivot_idx, col)
            mat.swap(pivot_row, pivot_idx); // Move pivot row up
            let pivot_val = mat[pivot_row][col];

            // Eliminate entries below the pivot
            for i in (pivot_row + 1)..n {
                let factor = mat[i][col];
                if factor != 0 {
                    // Use GCD-based elimination: R_i = (pivot/g) * R_i - (factor/g) * R_pivot
                    let g = crate::ring::helper::gcd(pivot_val, factor);

                    // Perform integer division first
                    let p_prime = pivot_val / g;
                    let f_prime = factor / g;

                    // Apply to the whole row (from 'col' onwards) using ring operations
                    for j in col..m_vars {
                        let term1 = ring.mul(p_prime, mat[i][j]);
                        let term2 = ring.mul(f_prime, mat[pivot_row][j]);
                        mat[i][j] = ring.sub(term1, term2);
                    }
                }
            }
            pivot_row += 1; // Move to next row for next pivot
            rank += 1; // Increment rank for each pivot found
        }
        // If no pivot in this column, move to the next column
    }

    Ok(rank)
}

/// Attempts to find the inverse of a square matrix modulo `m`.
pub fn matrix_inverse(matrix: &Matrix, ring: &Ring) -> Result<Matrix, SLECryptoError> {
    let n = matrix.len();
    // empty = empty
    if n == 0 {
        return Ok(Vec::new());
    }
    // check square
    for row in matrix.iter() {
        if row.len() != n {
            return Err(SLECryptoError::DimensionMismatch(
                "matrix_inverse: matrix must be square".into(),
            ));
        }
    }

    // normalize into an explicit Vec<Vec<i64>>
    let a: Matrix = matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|&v| ring.normalize(v).rem_euclid(ring.modulus() as i64))
                .collect()
        })
        .collect();

    // We'll build inverse one column at a time:
    // solve A x = e_j  (mod m)
    let m = ring.modulus();
    let mut inv = vec![vec![0; n]; n];

    for j in 0..n {
        // RHS = standard basis vector e_j
        let mut b = vec![0; n];
        b[j] = 1;
        // call your solver
        let x = solve(&a, &b, ring).ok_or_else(|| {
            SLECryptoError::InternalError(format!(
                "matrix_inverse: system A x = e_{} had no solution mod {}",
                j, m
            ))
        })?;
        // copy x into column j of inv
        for i in 0..n {
            inv[i][j] = x[i].rem_euclid(m as i64);
        }
    }

    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ring() -> Ring {
        Ring::try_with(13).unwrap()
    }

    #[test]
    fn test_vector_add_ok() {
        let ring = test_ring();
        let a = vec![1, 2, 3];
        let b = vec![10, 11, 12];
        let expected = vec![11, 0, 2]; // (1+10)%13=11, (2+11)%13=0, (3+12)%13=15%13=2
        assert_eq!(vector_add(&a, &b, &ring).unwrap(), expected);
    }

    #[test]
    fn test_vector_add_dimension_mismatch() {
        let ring = test_ring();
        let a = vec![1, 2, 3];
        let b = vec![10, 11];
        assert!(vector_add(&a, &b, &ring).is_err());
    }

    #[test]
    fn test_vector_sub_ok() {
        let ring = test_ring();
        let a = vec![1, 2, 3];
        let b = vec![10, 1, 5];
        let expected = vec![4, 1, 11]; // (1-10)%13 = -9%13 = 4, (2-1)%13 = 1, (3-5)%13 = -2%13 = 11
        assert_eq!(vector_sub(&a, &b, &ring).unwrap(), expected);
    }

    #[test]
    fn test_matrix_vector_mul_ok() {
        let ring = test_ring();
        let a = vec![vec![1, 2], vec![3, 4]];
        let x = vec![5, 6];
        // R1: (1*5 + 2*6) % 13 = (5 + 12) % 13 = 17 % 13 = 4
        // R2: (3*5 + 4*6) % 13 = (15 + 24) % 13 = (2 + 11) % 13 = 13 % 13 = 0
        let expected = vec![4, 0];
        assert_eq!(matrix_vector_mul(&a, &x, &ring).unwrap(), expected);
    }

    #[test]
    fn test_matrix_vector_mul_ok_2() {
        let ring = test_ring();
        let a = vec![vec![1, 2], vec![3, 4]];
        let x = vec![5, 6];
        // R1: (1*5 + 2*6) % 13 = (5 + 12) % 13 = 17 % 13 = 4
        // R2: (3*5 + 4*6) % 13 = (15 + 24) % 13 = (2 + 11) % 13 = 13 % 13 = 0
        let expected = vec![4, 0];
        assert_eq!(matrix_vector_mul(&a, &x, &ring).unwrap(), expected);
    }

    #[test]
    fn test_matrix_vector_mul_dimension_mismatch() {
        let ring = test_ring();
        let a = vec![vec![1, 2], vec![3, 4]];
        let x = vec![5, 6, 7]; // Incorrect dimension
        assert!(matrix_vector_mul(&a, &x, &ring).is_err());
    }

    #[test]
    fn test_matrix_mul_ok() {
        let ring = test_ring();
        let a = vec![vec![1, 2], vec![3, 4]]; // 2x2
        let b = vec![vec![5, 6], vec![7, 8]]; // 2x2
        // C[0][0] = (1*5 + 2*7) % 13 = (5 + 14) % 13 = (5 + 1) % 13 = 6
        // C[0][1] = (1*6 + 2*8) % 13 = (6 + 16) % 13 = (6 + 3) % 13 = 9
        // C[1][0] = (3*5 + 4*7) % 13 = (15 + 28) % 13 = (2 + 2) % 13 = 4
        // C[1][1] = (3*6 + 4*8) % 13 = (18 + 32) % 13 = (5 + 6) % 13 = 11
        let expected = vec![vec![6, 9], vec![4, 11]];
        assert_eq!(matrix_mul(&a, &b, &ring).unwrap(), expected);
    }

    #[test]
    fn test_matrix_mul_dimension_mismatch() {
        let ring = test_ring();
        let a = vec![vec![1, 2], vec![3, 4]]; // 2x2
        let b = vec![vec![5, 6, 7], vec![8, 9, 10]]; // 2x3 -> Should work
        let _ = matrix_mul(&a, &b, &ring).unwrap(); // This should pass

        let c = vec![vec![1], vec![2]]; // 2x1
        let d = vec![vec![3, 4]]; // 1x2
        let _ = matrix_mul(&c, &d, &ring).unwrap(); // This should pass

        let e = vec![vec![1, 2], vec![3, 4]]; // 2x2
        let f = vec![vec![1], vec![2], vec![3]]; // 3x1 -> Should fail
        assert!(matrix_mul(&e, &f, &ring).is_err());
    }

    #[test]
    fn test_identity_matrix() {
        let expected3 = vec![vec![1, 0, 0], vec![0, 1, 0], vec![0, 0, 1]];
        assert_eq!(identity_matrix(3), expected3);
        let expected1 = vec![vec![1]];
        assert_eq!(identity_matrix(1), expected1);
        let expected0: Matrix = Vec::new();
        assert_eq!(identity_matrix(0), expected0);
    }

    #[test]
    fn test_matrix_inverse_ok() {
        let ring = Ring::try_with(26).unwrap(); // Common for crypto examples like Hill cipher
        let matrix = vec![vec![3, 3], vec![2, 5]];
        // Inverse should be [[19, 21], [20, 9]] mod 26
        // Check: A * A^-1 = I (mod 26)
        // [3, 3] * [19, 21] = [ 3*19+3*20,  3*21+3*9 ] = [ 57+60, 63+27 ] = [ 117, 90 ] = [ 13, 12 ] mod 26  <- ERROR in manual calc? let's trust the code result
        // [2, 5]   [20,  9]   [ 2*19+5*20,  2*21+5*9 ] = [ 38+100, 42+45 ] = [ 138, 87 ] = [ 8, 9 ] mod 26 <- ERROR in manual calc
        // Let's recompute inverse manually:
        // det = 3*5 - 3*2 = 15 - 6 = 9.
        // det_inv = 9^-1 mod 26. 9 * 3 = 27 = 1 mod 26. So inv is 3.
        // adj = [[5, -3], [-2, 3]] mod 26 = [[5, 23], [24, 3]]
        // inv = 3 * [[5, 23], [24, 3]] = [[15, 69], [72, 9]] = [[15, 17], [20, 9]] mod 26
        let expected_inv = vec![vec![15, 17], vec![20, 9]];
        match matrix_inverse(&matrix, &ring) {
            Ok(inv) => assert_eq!(inv, expected_inv),
            Err(e) => panic!("Inversion failed: {:?}", e),
        }

        // Verify A * inv(A) = I
        let product = matrix_mul(&matrix, &expected_inv, &ring).unwrap();
        assert_eq!(product, identity_matrix(2));
    }

    #[test]
    fn test_matrix_inverse_singular() {
        let ring = test_ring(); // mod 13
        let matrix = vec![vec![1, 2], vec![2, 4]]; // Row 2 is 2*Row 1
        // Determinant = 1*4 - 2*2 = 0 mod 13
        assert!(matrix_inverse(&matrix, &ring).is_err());
    }

    #[test]
    fn test_matrix_rank_simple() {
        let ring = test_ring(); // mod 13
        let matrix = vec![vec![1, 2, 3], vec![2, 4, 6], vec![0, 1, 1]];
        // Row 2 is dependent on Row 1. Should have rank 2.
        assert_eq!(matrix_rank(&matrix, &ring).unwrap(), 2);

        let matrix2 = vec![vec![1, 0, 0], vec![0, 1, 0], vec![0, 0, 1]];
        assert_eq!(matrix_rank(&matrix2, &ring).unwrap(), 3);

        let matrix3 = vec![vec![1, 1], vec![1, 1]];
        assert_eq!(matrix_rank(&matrix3, &ring).unwrap(), 1);

        let matrix4 = vec![vec![0, 0], vec![0, 0]];
        assert_eq!(matrix_rank(&matrix4, &ring).unwrap(), 0);
    }
}
