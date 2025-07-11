import JWT from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { NotAuthorizedError } from './error-handler';

const tokens: string[] = [
  'auth',
  'seller',
  'gig',
  'search',
  'buyer',
  'message',
  'order',
  'review',
];

export function verifyGatewayRequest(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.headers?.gatewayToken) {
    throw new NotAuthorizedError(
      'Invalid request',
      'gateway-middleware.ts: verifyGatewayRequest()'
    );
  }

  const token: string = req.headers?.gatewayToken as string;
  if (!token) {
    throw new NotAuthorizedError(
      'Invalid request',
      'gateway-middleware.ts: verifyGatewayRequest()'
    );
  }

  try {
    const payload: { id: string; iat: number } = JWT.verify(
      token,
      'secret'
    ) as { id: string; iat: number };

    if (!tokens.includes(payload.id)) {
      throw new NotAuthorizedError(
        'Invalid request',
        'gateway-middleware.ts: verifyGatewayRequest()'
      );
    }
  } catch (error) {
    throw new NotAuthorizedError(
      'Invalid request',
      'gateway-middleware.ts: verifyGatewayRequest()'
    );
  }
}
