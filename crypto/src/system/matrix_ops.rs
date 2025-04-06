use crate::ring::Ring;

use crate::system::errors::CryptoError;

// --- Matrix/Vector Types ---
pub type Vector = Vec<i64>;
pub type Matrix = Vec<Vec<i64>>;

// --- Basic Operations (Modulo m) ---

/// Computes y = Ax (mod m)
pub fn matrix_vector_mul(a: &Matrix, x: &Vector, ring: &Ring) -> Result<Vector, CryptoError> {
    let n = a.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let m_vars = a[0].len();
    if x.len() != m_vars {
        return Err(CryptoError::DimensionMismatch(format!(
            "Matrix columns ({}) must match vector length ({})",
            m_vars,
            x.len()
        )));
    }

    let mut y = vec![0; n];
    for i in 0..n {
        if a[i].len() != m_vars {
            return Err(CryptoError::DimensionMismatch(format!(
                "Matrix row {} has length {} but expected {}",
                i,
                a[i].len(),
                m_vars
            )));
        }
        let mut sum = 0i64;
        for (&a_val, &x_val) in a[i].iter().zip(x.iter()) {
            let term = ring.mul(a_val, x_val);
            sum = ring.add(sum, term);
        }
        y[i] = sum; // Already normalized by ring operations
    }
    Ok(y)
}

/// Computes c = a + b (mod m) for vectors
pub fn vector_add(a: &Vector, b: &Vector, ring: &Ring) -> Result<Vector, CryptoError> {
    if a.len() != b.len() {
        return Err(CryptoError::DimensionMismatch(format!(
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

/// Computes c = a - b (mod m) for vectors
pub fn vector_sub(a: &Vector, b: &Vector, ring: &Ring) -> Result<Vector, CryptoError> {
    if a.len() != b.len() {
        return Err(CryptoError::DimensionMismatch(format!(
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

// --- Matrix Inversion (for square matrices) ---
// Removed unused determinant function

/// Attempts to find the inverse of a square matrix modulo m using Gaussian elimination.
/// Returns Ok(inverse_matrix) or Err if not invertible or other error.
pub fn matrix_inverse(matrix: &Matrix, ring: &Ring) -> Result<Matrix, CryptoError> {
    let n = matrix.len();
    if n == 0 {
        return Ok(Matrix::new());
    }
    // Check if square
    for row in matrix {
        if row.len() != n {
            return Err(CryptoError::DimensionMismatch(
                "Matrix must be square for inversion".to_string(),
            ));
        }
    }

    // Create augmented matrix [A | I]
    let mut aug = Vec::with_capacity(n);
    for (i, row_vec) in matrix.iter().enumerate() {
        let mut row = row_vec.clone();
        for j in 0..n {
            row.push(if i == j { 1 } else { 0 });
        }
        // Normalize row
        for val in row.iter_mut() {
            *val = ring.normalize(*val);
        }
        aug.push(row);
    }

    // Gaussian elimination to get [I | A^-1]
    for i in 0..n {
        // Target row i
        // Find pivot in column i at or below row i
        let mut pivot_row = i;
        while pivot_row < n && aug[pivot_row][i] == 0 {
            pivot_row += 1;
        }

        if pivot_row == n {
            // No pivot found in this column -> matrix is singular
            return Err(CryptoError::InternalError(format!(
                "Matrix is singular (no pivot found for column {})",
                i
            )));
        }

        // Swap rows to bring pivot to diagonal
        aug.swap(i, pivot_row);

        // Make pivot element 1
        let pivot_val = aug[i][i];
        let inv = ring.inv(pivot_val).map_err(|_| {
            CryptoError::InternalError(format!(
                "Matrix is singular (pivot {} in row {} has no inverse mod {})",
                pivot_val,
                i,
                ring.modulus()
            ))
        })?;

        // Multiply pivot row by inverse
        for j in i..(2 * n) {
            aug[i][j] = ring.mul(aug[i][j], inv);
        }

        // Eliminate other entries in column i
        for row_idx in 0..n {
            if row_idx != i {
                let factor = aug[row_idx][i];
                if factor != 0 {
                    // R_row_idx = R_row_idx - factor * R_i
                    for col_idx in i..(2 * n) {
                        let term = ring.mul(factor, aug[i][col_idx]);
                        aug[row_idx][col_idx] = ring.sub(aug[row_idx][col_idx], term);
                    }
                }
            }
        }
    }

    // Extract inverse matrix [A^-1] from the right side
    let mut inv_matrix = vec![vec![0; n]; n];
    for i in 0..n {
        for j in 0..n {
            inv_matrix[i][j] = aug[i][n + j];
        }
    }

    Ok(inv_matrix)
}

/// Calculates the rank of a matrix modulo m.
/// Rank is the number of linearly independent rows (or columns).
/// This uses Gaussian elimination.
pub fn matrix_rank(matrix: &Matrix, ring: &Ring) -> Result<usize, CryptoError> {
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
            return Err(CryptoError::DimensionMismatch(format!(
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
            let pivot_val = mat[pivot_row][col]; // Non-zero

            // Eliminate entries below the pivot
            for i in (pivot_row + 1)..n {
                let factor = mat[i][col];
                if factor != 0 {
                    // Use GCD-based elimination: R_i = (pivot/g) * R_i - (factor/g) * R_pivot
                    let g = crate::helper::gcd(pivot_val, factor); // Assuming helper::gcd exists
                    if g == 0 {
                        // Should not happen if pivot_val != 0
                        return Err(CryptoError::InternalError(
                            "GCD calculation resulted in zero".to_string(),
                        ));
                    }

                    // Perform integer division first
                    let p_prime = pivot_val / g; // Integer division
                    let f_prime = factor / g; // Integer division

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
