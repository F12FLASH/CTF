import { config } from 'dotenv';
import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import { submissions } from "@shared/schema";

config();

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

export const sql = neon(process.env.DATABASE_URL);
export const db = drizzle({ client: sql });

export { submissions };
