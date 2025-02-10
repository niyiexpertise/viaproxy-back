import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { validateEnv } from '../config/env.config';
import { ErrorCode } from '../errors/custom.errors';
import ForbiddenError from '../errors/forbidden.errors';
import NotFoundError from '../errors/notFound.errors';
import UnAuthenticatedError from '../errors/unauthenticated.errors';
import { IRole } from '../interface/roles.interface';
import { IUser } from '../interface/user.interface';
import { findExtendedUsers } from '../services/user.services';
import { extractTokenfromHeader } from '../utils/util';

export interface UserDataType {
  userId: string;
  permission?: IRole['permissions'];
  role?: IRole;
}
export interface IUserMessage<TParams = any, TQuery = any, TBody = any> extends Request<TParams, TQuery, TBody> {
  userData: UserDataType;
}
type ExtendedUser = IUser & {
  permission?: IRole;
};
export const AuthJWT = (req: IUserMessage, res: Response, next: NextFunction) => {
  try {
    const jwtconfig = validateEnv()?.jwtconfig;
    const token = extractTokenfromHeader(req);
    if (!token) throw new UnAuthenticatedError('Provide token', ErrorCode.TOKEN_NOT_FOUND);
    jwt.verify(token, jwtconfig?.accessSecret, async (err, decoded) => {
      if (err) return next(new ForbiddenError('Token expires', ErrorCode?.TOKEN_EXPIRE));
      const decodeData = decoded as UserDataType;
      const userWithPermission = await findExtendedUsers(decodeData?.userId);
      if (!userWithPermission) throw new NotFoundError('User not found', ErrorCode.NOT_FOUND);
      req.userData = {
        userId: decodeData?.userId,
        permission: userWithPermission?.role?.permissions,
        role: userWithPermission.role,
      };
      next();
    });
  } catch (err) {
    throw new UnAuthenticatedError('Provide token', ErrorCode.TOKEN_NOT_FOUND);
  }
};
