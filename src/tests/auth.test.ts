import request from 'supertest';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import app from '../app'; // Path to your Express app
import prisma from '../prisma';

describe('User Authentication Tests', () => {
  beforeAll(async () => {
    await prisma.user.deleteMany(); // Clear existing users if any
  });

  afterAll(async () => {
    await prisma.$disconnect(); // Disconnect from Prisma after all tests
  });

  describe('Cookie-based Authentication', () => {
    it('should sign up a new user and set a cookie with JWT', async () => {

      const response = await request(app)
        .post('/signup')
        .send({
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          password: 'Password123!',
          userType: 'student',
        });

      expect(response.status).toBe(201);

      expect(response.headers['set-cookie']).toBeDefined();

      const cookies = response.headers['set-cookie'];
      expect(cookies[0]).toMatch(/jwt=/);
    });

    it('should allow access to a protected route with a valid JWT in cookies', async () => {
      const signupResponse = await request(app)
        .post('/signup')
        .send({
          fullName: 'Jane Doe',
          email: 'jane.doe@example.com',
          password: 'Password123!',
          userType: 'teacher',
        });

      const cookies = signupResponse.headers['set-cookie'];

      const response = await request(app)
        .get('/protected-route')
        .set('Cookie', cookies);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'success');
      expect(response.body).toHaveProperty('message', 'You have access to this protected route.');
    });

    it('should reject access to a protected route without a cookie', async () => {
      const response = await request(app).get('/protected-route');
      expect(response.status).toBe(401); // Expect unauthorized access
      expect(response.body).toHaveProperty('message', 'You are not logged in! Please log in to get access.');
    });

    it('should reject access to a protected route with an invalid JWT in the cookie', async () => {
      const invalidCookie = 'jwt=invalidtoken123';

      const response = await request(app)
        .get('/protected-route')
        .set('Cookie', invalidCookie);

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message', 'Invalid token. Please log in again.');
    });
  });

  describe('Bearer Token Authentication', () => {
    it('should return a valid JWT token upon successful sign-up', async () => {
      const response = await request(app)
        .post('/signup')
        .send({
          fullName: 'Alice Doe',
          email: 'alice.doe@example.com',
          password: 'Password123!',
          userType: 'student',
        });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('token');

      const token = response.body.token;
      expect(token).toBeDefined();
    });

    it('should allow access to a protected route with a valid JWT Bearer token', async () => {
      const signupResponse = await request(app)
        .post('/signup')
        .send({
          fullName: 'Bob Doe',
          email: 'bob.doe@example.com',
          password: 'Password123!',
          userType: 'student',
        });

      const token = signupResponse.body.token;

      const response = await request(app)
        .get('/protected-route')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'success');
      expect(response.body).toHaveProperty('message', 'You have access to this protected route.');
    });

    it('should reject access to a protected route without a Bearer token', async () => {
      const response = await request(app).get('/protected-route');

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message', 'You are not logged in! Please log in to get access.');
    });

    it('should reject access to a protected route with an invalid Bearer token', async () => {
      const invalidToken = 'Bearer invalidtoken123';

      const response = await request(app)
        .get('/protected-route')
        .set('Authorization', invalidToken);

      expect(response.status).toBe(401); // Expect unauthorized access
      expect(response.body).toHaveProperty('message', 'Invalid token. Please log in again.');
    });
  });

  describe('GET /user/:id', () => {
    let userId: string;

    beforeAll(async () => {
      const user = await prisma.user.create({
        data: {
          fullName: 'John Doe',
          email: 'john.doe+test1@example.com', // Unique email
          password: 'Password123!',
          userType: 'student',
        },
      });
      userId = user.id;
    });

    it('should return a user by ID', async () => {
      const response = await request(app).get(`/user/${userId}`);

      expect(response.status).toBe(200); // Expect successful retrieval
      expect(response.body).toHaveProperty('status', 'success');
      expect(response.body.data.user).toHaveProperty('id', userId); // Check if the returned user matches the ID
      expect(response.body.data.user).toHaveProperty('fullName', 'John Doe');
      expect(response.body.data.user).toHaveProperty('email', 'john.doe+test1@example.com');
    });

    it('should return 404 if user is not found', async () => {
      const response = await request(app).get('/user/non-existent-id');

      expect(response.status).toBe(404); // Expect user not found status
      expect(response.body).toHaveProperty('status', 'fail');
      expect(response.body).toHaveProperty('message', 'User not found with ID: non-existent-id');
    });
  });
});
