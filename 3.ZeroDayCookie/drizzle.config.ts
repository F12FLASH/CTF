import { defineConfig } from "drizzle-kit";
import { readFileSync } from 'fs';
import { resolve } from 'path';

// Đọc file .env thủ công
function loadEnv() {
  try {
    const envPath = resolve('.env');
    const envFile = readFileSync(envPath, 'utf8');
    const envVars = envFile.split('\n');
    
    for (const line of envVars) {
      const [key, ...value] = line.split('=');
      if (key && value.length > 0) {
        process.env[key] = value.join('=').replace(/"/g, '').trim();
      }
    }
  } catch (error) {
    console.log('Không tìm thấy file .env, sử dụng biến môi trường hệ thống');
  }
}

// Load biến môi trường
loadEnv();

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing, ensure the database is provisioned");
}

export default defineConfig({
  out: "./migrations",
  schema: "./shared/schema.ts",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL,
  },
});