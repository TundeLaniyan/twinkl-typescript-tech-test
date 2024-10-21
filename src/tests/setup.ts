import { PrismaClient } from '@prisma/client';
import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { execFile } from 'child_process';
import path from 'path';
import { beforeAll, afterAll } from 'vitest';

let postgresContainer: StartedPostgreSqlContainer;
let prisma: PrismaClient;

/**
 * Runs Prisma migrations using child_process.execFile.
 * This ensures that the Prisma schema is applied to the database before tests.
 */
async function runPrismaDbPush() {
    return new Promise<void>((resolve, reject) => {
        execFile(
            path.resolve('./node_modules/prisma/build/index.js'),
            ['db', 'push', '--skip-generate'],
            (error, stdout, stderr) => {
                console.log(stdout);
                if (error) {
                    console.error(`Prisma db push failed: ${error.message}`);
                    reject(error);
                } else {
                    console.log('Prisma db push completed successfully.');
                    resolve();
                }
            }
        );
    });
}

beforeAll(async () => {
    // Start the PostgreSQL container
    postgresContainer = await new PostgreSqlContainer()
        .withDatabase('mydb')
        .withUsername('postgres')
        .withPassword('password')
        .start();

    const databaseUrl = postgresContainer.getConnectionUri();


    // Set environment variable for Prisma client
    process.env.DATABASE_URL = databaseUrl;
    process.env.JWT_SECRET = 'your_jwt_secret_key'
    process.env.JWT_EXPIRES_IN = '90d'
    process.env.JWT_COOKIE_EXPIRES_IN = '90'


    // Initialize Prisma client
    prisma = new PrismaClient();
    await prisma.$connect();

    // Run Prisma db push to apply the schema to the database
    await runPrismaDbPush();
});

afterAll(async () => {
    // Disconnect Prisma and stop the container after all tests
    if (prisma) {
        await prisma.$disconnect();
    }
    if (postgresContainer) {
        await postgresContainer.stop();
    }
});
