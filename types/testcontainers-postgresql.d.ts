declare module '@testcontainers/postgresql' {
    export class PostgreSqlContainer {
        constructor(image?: string);

        // Starts the container and returns an instance of itself
        start(): Promise<StartedPostgreSqlContainer>;

        stop(): Promise<void>;

        withDatabase(database: string): this;

        withUsername(username: string): this;

        withPassword(password: string): this;

        withExposedPorts(...ports: number[]): this;
    }

    export class StartedPostgreSqlContainer {
        getConnectionUri(): string
        // Methods available after the container has started
        getPort(): number;

        getUsername(): string;

        getPassword(): string;

        getDatabase(): string;

        stop(): Promise<void>;
    }
}
