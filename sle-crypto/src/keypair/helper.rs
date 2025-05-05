use crate::ring::{Matrix, Vector};

/// Maps each element of a matrix using the provided mapping function.
///
/// # Arguments
/// * `matrix` - The input matrix to transform
/// * `mapper` - A function that maps each element
///
/// # Returns
/// A new matrix with each element transformed by the mapper function
pub fn map_matrix(matrix: &Matrix, mapper: &dyn Fn(i64) -> i64) -> Matrix {
    matrix
        .iter()
        .map(|row| row.iter().map(|&val| mapper(val)).collect())
        .collect()
}

/// Maps each element of a vector using the provided mapping function.
///
/// # Arguments
/// * `vector` - The input vector to transform
/// * `mapper` - A function that maps each element
///
/// # Returns
/// A new vector with each element transformed by the mapper function
pub fn map_vector(vector: &Vector, mapper: &dyn Fn(i64) -> i64) -> Vector {
    vector.iter().map(|&val| mapper(val)).collect()
}
