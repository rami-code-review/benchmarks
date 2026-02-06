/**
 * Service layer with database operations.
 */

import { User } from './api';

export interface DatabaseClient {
  query(sql: string, params: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * UserService handles user data operations.
 * Uses parameterized queries for all database operations.
 */
export class UserService {
  constructor(private db: DatabaseClient) {}

  /**
   * Find user by ID.
   *
   * SAFE VERSION: Uses parameterized query.
   * Matches template: ts-multifile-sqli-safe (receiver)
   */
  async findById(userId: string): Promise<User | null> {
    const result = await this.db.query(
      'SELECT id, name, email FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0] as { id: number; name: string; email: string };
    return { id: row.id, name: row.name, email: row.email };
  }

  /**
   * Find user by email.
   *
   * SAFE VERSION: Uses parameterized query.
   */
  async findByEmail(email: string): Promise<User | null> {
    const result = await this.db.query(
      'SELECT id, name, email FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0] as { id: number; name: string; email: string };
    return { id: row.id, name: row.name, email: row.email };
  }

  /**
   * Search users by name.
   *
   * SAFE VERSION: Uses parameterized LIKE query.
   * Matches template: ts-multifile-sqli-search-safe (receiver)
   */
  async search(query: string): Promise<User[]> {
    const result = await this.db.query(
      'SELECT id, name, email FROM users WHERE name LIKE $1',
      [`%${query}%`]
    );

    return result.rows.map((row: unknown) => {
      const r = row as { id: number; name: string; email: string };
      return { id: r.id, name: r.name, email: r.email };
    });
  }

  /**
   * Create a new user.
   *
   * SAFE VERSION: Uses parameterized insert.
   */
  async create(name: string, email: string): Promise<User> {
    const result = await this.db.query(
      'INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id',
      [name, email]
    );

    const row = result.rows[0] as { id: number };
    return { id: row.id, name, email };
  }

  /**
   * Delete a user.
   *
   * SAFE VERSION: Uses parameterized delete.
   */
  async delete(userId: number): Promise<boolean> {
    const result = await this.db.query(
      'DELETE FROM users WHERE id = $1',
      [userId]
    );

    return (result as unknown as { rowCount: number }).rowCount > 0;
  }
}
