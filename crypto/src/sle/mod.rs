//! A module for solving systems of linear equations Ax = b
//! over the ring of integers modulo K (Z_K).
//!
//! This implementation uses Gaussian elimination adapted for modular arithmetic.
//! It works best when K is prime. If K is composite, it might fail or give
//! incorrect results if a required modular inverse doesn't exist.

mod errors;
pub use errors::SleError;

use crate::ring::math::Ring;

use crate::helper::gcd;
use std::fmt;

/// Represents the possible outcomes of solving a linear system modulo K.
#[derive(Debug, PartialEq, Eq)]
pub enum Solution {
    /// A unique solution vector x.
    Unique(Vec<i64>),
    /// No solution exists for the system.
    NoSolution,
    /// Infinitely many solutions exist.
    /// The Vec contains a particular solution (often with free variables set to 0),
    /// and the inner Vec<usize> contains the indices (0-based) of the free variables.
    Infinite(Vec<i64>, Vec<usize>),
}

impl fmt::Display for Solution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Solution::Unique(x) => write!(f, "Unique solution: {:?}", x),
            Solution::NoSolution => write!(f, "No solution"),
            Solution::Infinite(sol, free_vars) => write!(
                f,
                "Infinite solutions. Particular solution: {:?}, Free variables indices: {:?}",
                sol, free_vars
            ),
        }
    }
}

// --- Helper function to solve a single linear congruence ax = b (mod k) ---
/// Returns a list of solutions modulo k.
/// Returns Ok(empty_vec) if no solution exists.
/// Returns Ok(all_elements) if a=0, b=0 (0x=0).
fn solve_linear_congruence(a: i64, b: i64, ring: &Ring) -> Result<Vec<i64>, SleError> {
    let k = ring.modulus() as i64;
    let a_norm = ring.normalize(a);
    let b_norm = ring.normalize(b);

    if a_norm == 0 {
        return if b_norm == 0 {
            // 0x = 0 (mod k) -> Infinite solutions (all elements of Z_k)
            // In SLE context, this indicates a free variable.
            // Returning all solutions might be too much, maybe return special value?
            // For now, let's return a single solution (0) and let the main
            // solve function handle the free variable logic.
            // Or maybe return an indicator? Let's return all for completeness here.
            Ok((0..k).map(|i| ring.normalize(i)).collect())
        } else {
            // 0x = b (mod k) with b != 0 -> No solution
            Ok(Vec::new())
        };
    }

    let g = gcd(a_norm, k);

    if b_norm % g != 0 {
        // No solution exists if gcd(a, k) does not divide b
        Ok(Vec::new())
    } else {
        // Reduce the congruence: (a/g)x = (b/g) (mod k/g)
        let a_prime = a_norm / g; // Exact division
        let b_prime = b_norm / g; // Exact division
        let k_prime = k / g; // Exact division

        // Create a temporary ring for the reduced modulus
        // Handle edge case k_prime = 1 (means g=k)
        if k_prime == 1 {
            // Original congruence was ax = b (mod k) where gcd(a,k)=k.
            // This means a is a multiple of k (a=0 mod k).
            // We already handled a=0 case above. This path implies a!=0 initially
            // but a=0 mod k. And b must be divisible by g=k (b=0 mod k).
            // So it's 0x = 0 (mod k). All x are solutions.
            return Ok((0..k).map(|i| ring.normalize(i)).collect());
        }
        if k_prime <= 0 {
            // Should not happen if k > 1 initially
            return Err(SleError::InternalError(
                "Invalid reduced modulus k' <= 0".to_string(),
            ));
        }

        // gcd(a_prime, k_prime) is now 1, so inverse exists.
        let reduced_ring = Ring::try_with(k_prime as u64)?; // Use try_with

        // Find the inverse of a_prime modulo k_prime
        let inv_a_prime = match reduced_ring.inv(a_prime) {
            Ok(inv) => inv,
            Err(_) => {
                return Err(SleError::InternalError(format!(
                    "Failed to find inverse for {} mod {} (gcd should be 1)",
                    a_prime, k_prime
                )));
            }
        };

        // Calculate the unique solution x0 modulo k_prime
        let x0 = reduced_ring.mul(b_prime, inv_a_prime);

        // Generate all g solutions modulo k
        let mut solutions = Vec::with_capacity(g as usize);
        for i in 0..g {
            solutions.push(ring.normalize(x0 + i * k_prime));
        }
        solutions.sort_unstable(); // Optional: keep solutions ordered
        Ok(solutions)
    }
}

/// Solves the system of linear equations Ax = b modulo K.
/// K can be composite.
///
/// Args:
///   a: The coefficient matrix (n rows, m columns).
///   b: The constant vector (n elements).
///   k: The modulus (must be > 1).
///
/// Returns:
///   A `Result` containing either a `Solution` enum or an `SleError`.
pub fn solve(a: &[Vec<i64>], b: &[i64], k: u64) -> Result<Solution, SleError> {
    if k <= 1 {
        return Err(SleError::InvalidModulus);
    }

    let n = a.len(); // Number of equations
    // Determine number of variables (m). Handle empty 'a'.
    let m = if n > 0 {
        if a[0].is_empty() { 0 } else { a[0].len() }
    } else {
        0 // No equations, technically 0 variables unless b is non-empty?
    };

    // --- Dimension Checks ---
    if b.len() != n {
        return Err(SleError::DimensionMismatch(format!(
            "Matrix A rows ({}) must match vector b length ({})",
            n,
            b.len()
        )));
    }
    for (i, row) in a.iter().enumerate() {
        if row.len() != m {
            return Err(SleError::DimensionMismatch(format!(
                "Row {} in matrix A has length {} but expected {}",
                i,
                row.len(),
                m
            )));
        }
    }

    // --- Handle Edge Cases ---
    if n == 0 {
        // No equations
        if m == 0 {
            // No equations, no variables
            return Ok(Solution::Unique(Vec::new())); // Trivial solution
        } else {
            // No equations, m variables
            // All variables are free. Particular solution is all zeros.
            return Ok(Solution::Infinite(vec![0; m], (0..m).collect()));
        }
    }
    if m == 0 {
        // No variables, n equations
        let ring_temp = Ring::try_with(k)?; // Need ring for normalization
        for &bi in b {
            if ring_temp.normalize(bi) != 0 {
                return Ok(Solution::NoSolution); // Equation like 0 = c (c!=0)
            }
        }
        return Ok(Solution::Unique(Vec::new())); // All equations 0 = 0
    }

    // --- Setup ---
    let ring = Ring::try_with(k)?;

    // Create augmented matrix [A | b] and normalize
    let mut aug_matrix: Vec<Vec<i64>> = Vec::with_capacity(n);
    for i in 0..n {
        let mut row = a[i].clone();
        row.push(b[i]);
        for val in row.iter_mut() {
            *val = ring.normalize(*val);
        }
        aug_matrix.push(row);
    }

    // --- Forward Elimination (Gaussian Elimination for Rings) ---
    let mut pivot_row = 0;
    // Store the column index of the pivot in each row (-1 if no pivot)
    let mut pivot_cols = vec![-1; n];

    for col in 0..m {
        // Iterate through columns (potential pivot columns)
        if pivot_row >= n {
            break; // All rows have been processed or reduced to zero
        }

        // Find pivot row for this column (first non-zero below current pivot_row)
        let mut pivot_idx = pivot_row;
        while pivot_idx < n && aug_matrix[pivot_idx][col] == 0 {
            pivot_idx += 1;
        }

        if pivot_idx < n {
            // Found a pivot at (pivot_idx, col)
            aug_matrix.swap(pivot_row, pivot_idx); // Move pivot row up
            let pivot_val = aug_matrix[pivot_row][col]; // This is non-zero
            pivot_cols[pivot_row] = col as i32; // Record pivot column index for this row

            // Eliminate entries below the pivot in the current column
            for i in (pivot_row + 1)..n {
                let factor = aug_matrix[i][col];
                if factor != 0 {
                    // Use GCD-based elimination: R_i = (pivot/g) * R_i - (factor/g) * R_pivot
                    let g = gcd(pivot_val, factor);
                    let p_prime = pivot_val / g; // Exact division guaranteed
                    let f_prime = factor / g; // Exact division guaranteed

                    // Apply to the whole row (from 'col' onwards)
                    for j in col..=m {
                        let term1 = ring.mul(p_prime, aug_matrix[i][j]);
                        let term2 = ring.mul(f_prime, aug_matrix[pivot_row][j]);
                        aug_matrix[i][j] = ring.sub(term1, term2);
                    }
                    // aug_matrix[i][col] should now be 0
                }
            }
            pivot_row += 1; // Move to the next row for the next pivot
        }
        // If no pivot found in this column (all zeros below pivot_row),
        // this column corresponds to a free variable. Move to the next column.
    }

    let rank = pivot_row; // Number of non-zero rows after elimination

    // --- Check for Inconsistencies ---
    // Start from the last row processed by elimination up to the last equation
    // Use iterator for row access
    for row in aug_matrix.iter().skip(rank) {
        // Check if row[m] (the constant part) is non-zero
        if row[m] != 0 {
            // If we have 0 = c (where c != 0), the system is inconsistent
            return Ok(Solution::NoSolution);
        }
    }

    // --- Back Substitution ---
    let mut solution = vec![0; m];
    let mut is_pivot_var = vec![false; m];
    for i in (0..rank).rev() {
        let pivot_col = pivot_cols[i] as usize;
        is_pivot_var[pivot_col] = true;

        let mut rhs = aug_matrix[i][m];
        // Use iterator for the sum
        for (j, &coeff) in aug_matrix[i]
            .iter()
            .enumerate()
            .skip(pivot_col + 1)
            .take(m - (pivot_col + 1))
        {
            let term = ring.mul(coeff, solution[j]);
            rhs = ring.sub(rhs, term);
        }

        let pivot_val = aug_matrix[i][pivot_col];
        let sols = solve_linear_congruence(pivot_val, rhs, &ring)?;

        if sols.is_empty() {
            return Err(SleError::InternalError(format!(
                "Inconsistency detected during back-substitution for row {}, pivot col {}. Equation {}x = {} mod {}",
                i, pivot_col, pivot_val, rhs, k
            )));
        } else {
            solution[pivot_col] = sols[0];
        }
    }

    // --- Identify Free Variables ---
    let free_vars_indices: Vec<usize> = (0..m).filter(|&col| !is_pivot_var[col]).collect();

    // --- Return Solution Type ---
    if free_vars_indices.is_empty() {
        Ok(Solution::Unique(solution))
    } else {
        Ok(Solution::Infinite(solution, free_vars_indices))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Prime Modulus Tests ---
    #[test]
    fn test_solve_unique_prime_k() {
        // System:
        // 2x + 3y = 1 (mod 5)
        // 1x + 2y = 2 (mod 5)
        // Solution: x=1, y=3
        let a = vec![vec![2, 3], vec![1, 2]];
        let b = vec![1, 2];
        let k = 5;
        assert_eq!(solve(&a, &b, k).unwrap(), Solution::Unique(vec![1, 3]));
    }

    #[test]
    fn test_solve_unique_prime_k_3x3() {
        // System (mod 7):
        // 1x + 1y + 1z = 1
        // 0x + 2y + 5z = 2
        // 2x + 0y + 3z = 3
        // Solution: x=6, y=5, z=4
        let a = vec![vec![1, 1, 1], vec![0, 2, 5], vec![2, 0, 3]];
        let b = vec![1, 2, 3];
        let k = 7;
        assert_eq!(solve(&a, &b, k).unwrap(), Solution::Unique(vec![6, 5, 4]));
    }

    #[test]
    fn test_solve_infinite_prime_k() {
        // System:
        // 1x + 1y = 1 (mod 5)
        // 2x + 2y = 2 (mod 5)
        // Dependent equations, infinite solutions. Rank 1, Vars 2. Free var y (index 1).
        // Particular solution (set y=0): x=1. sol=[1, 0]
        let a = vec![vec![1, 1], vec![2, 2]];
        let b = vec![1, 2];
        let k = 5;
        match solve(&a, &b, k).unwrap() {
            Solution::Infinite(sol, free) => {
                assert_eq!(free, vec![1]); // y is free variable
                assert_eq!(sol, vec![1, 0]); // Particular solution with y=0
            }
            other => panic!("Expected infinite solutions, got {:?}", other),
        }
    }

    #[test]
    fn test_solve_no_solution_prime_k() {
        // System:
        // 1x + 1y = 1 (mod 5)
        // 1x + 1y = 2 (mod 5) -> 0 = 1 after R2 = R2 - R1
        let a = vec![vec![1, 1], vec![1, 1]];
        let b = vec![1, 2];
        let k = 5;
        assert_eq!(solve(&a, &b, k).unwrap(), Solution::NoSolution);
    }

    // --- Composite Modulus Tests ---
    #[test]
    fn test_solve_unique_composite_k() {
        // System (mod 6):
        // 1x + 1y = 5
        // 0x + 5y = 1
        // From R2: 5y=1 (mod 6). inv(5)=5. y = 1*5 = 5.
        // From R1: x + 5 = 5 => x = 0.
        // Solution: x=0, y=5
        let a = vec![vec![1, 1], vec![0, 5]];
        let b = vec![5, 1];
        let k = 6;
        assert_eq!(solve(&a, &b, k).unwrap(), Solution::Unique(vec![0, 5]));
    }

    #[test]
    fn test_solve_paper_example_step_mod25() {
        // From paper Example 3, solving for x2, x3 in Z_25:
        // 6x + 9y = 18 (mod 25)
        // 1x + 11y = 0 (mod 25)
        // Solution: x=14, y=1
        let a = vec![vec![6, 9], vec![1, 11]];
        let b = vec![18, 0];
        let k = 25;
        match solve(&a, &b, k).unwrap() {
            Solution::Unique(sol) => assert_eq!(sol, vec![14, 1]),
            other => panic!("Expected unique solution, got {:?}", other),
        }
    }

    #[test]
    fn test_solve_no_solution_composite() {
        // System:
        // 2x + 3y = 1 (mod 6)
        // 4x + 0y = 1 (mod 6) -> 4x = 1 (mod 6). gcd(4,6)=2. 1%2 != 0. No solution.
        let a = vec![vec![2, 3], vec![4, 0]];
        let b = vec![1, 1];
        let k = 6;
        assert_eq!(solve(&a, &b, k).unwrap(), Solution::NoSolution);

        // System:
        // 1x + 1y = 1 (mod 4)
        // 2x + 2y = 3 (mod 4) -> R2 = R2 - 2*R1 => 0x + 0y = 3 - 2*1 = 1 (mod 4). No solution.
        let a2 = vec![vec![1, 1], vec![2, 2]];
        let b2 = vec![1, 3];
        let k2 = 4;
        assert_eq!(solve(&a2, &b2, k2).unwrap(), Solution::NoSolution);
    }

    #[test]
    fn test_solve_infinite_solutions_composite_free_var() {
        // System:
        // 1x + 1y = 2 (mod 6)
        // 2x + 2y = 4 (mod 6) -> R2 = R2 - 2*R1 => 0x + 0y = 4 - 2*2 = 0 (mod 6).
        // Dependent equations. Rank 1, Vars 2. Free var y (index 1).
        // From R1: x + y = 2. Particular solution (set y=0): x=2. sol=[2, 0]
        let a = vec![vec![1, 1], vec![2, 2]];
        let b = vec![2, 4]; // Changed b from previous test
        let k = 6;
        match solve(&a, &b, k).unwrap() {
            Solution::Infinite(sol, free) => {
                assert_eq!(free, vec![1]); // y is free variable
                assert_eq!(sol, vec![2, 0]); // Particular solution with y=0
                // Verify particular solution
                let ring = Ring::try_with(k).unwrap();
                assert_eq!(
                    ring.add(ring.mul(a[0][0], sol[0]), ring.mul(a[0][1], sol[1])),
                    ring.normalize(b[0])
                );
            }
            other => panic!("Expected infinite solutions, got {:?}", other),
        }
    }

    // --- Edge Case and Error Tests ---
    #[test]
    fn test_invalid_modulus() {
        let a = vec![vec![1, 1]];
        let b = vec![1];
        assert!(matches!(solve(&a, &b, 1), Err(SleError::InvalidModulus)));
        assert!(matches!(solve(&a, &b, 0), Err(SleError::InvalidModulus)));
    }

    #[test]
    fn test_dimension_mismatch_b() {
        let a = vec![vec![1, 2], vec![3, 4]]; // 2x2
        let b = vec![1]; // length 1
        let k = 5;
        assert!(matches!(
            solve(&a, &b, k),
            Err(SleError::DimensionMismatch(_))
        ));
    }

    #[test]
    fn test_dimension_mismatch_a_rows() {
        let a = vec![vec![1, 2], vec![3]]; // 2 rows, inconsistent cols
        let b = vec![1, 2];
        let k = 5;
        assert!(matches!(
            solve(&a, &b, k),
            Err(SleError::DimensionMismatch(_))
        ));
    }

    #[test]
    fn test_empty_a_matrix() {
        let a: Vec<Vec<i64>> = vec![];
        let b: Vec<i64> = vec![];
        let k = 5;
        // 0 equations, 0 variables
        assert_eq!(solve(&a, &b, k).unwrap(), Solution::Unique(vec![]));

        let b2 = vec![1]; // 0 equations, but b is non-empty -> error?
        // Let's refine the check: n=0 means b must be empty.
        assert!(matches!(
            solve(&a, &b2, k),
            Err(SleError::DimensionMismatch(_))
        ));

        let a3 = vec![vec![], vec![]]; // 2 equations, 0 variables
        let b3 = vec![0, 0];
        assert_eq!(solve(&a3, &b3, k).unwrap(), Solution::Unique(vec![]));

        let b4 = vec![0, 1]; // 0 = 1 -> No solution
        assert_eq!(solve(&a3, &b4, k).unwrap(), Solution::NoSolution);
    }

    #[test]
    fn test_zero_matrix() {
        let a = vec![vec![0, 0], vec![0, 0]];
        let b = vec![0, 0];
        let k = 6;
        // 0x+0y=0, 0x+0y=0. Rank 0, Vars 2. Infinite. Free vars x,y (0, 1).
        // Particular sol [0,0].
        match solve(&a, &b, k).unwrap() {
            Solution::Infinite(sol, free) => {
                assert_eq!(free, vec![0, 1]);
                assert_eq!(sol, vec![0, 0]);
            }
            other => panic!("Expected infinite, got {:?}", other),
        }

        let b2 = vec![0, 1]; // 0x+0y=1 -> No solution
        assert_eq!(solve(&a, &b2, k).unwrap(), Solution::NoSolution);
    }
}
