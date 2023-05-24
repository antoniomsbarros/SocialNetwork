import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import { argon2d } from 'argon2';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signin(dto: AuthDto) {
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
    if (!user) {
      throw new ForbiddenException(
        'Credentials taken',
      );
    }
    const pwdmatch = await argon.verify(
      user.hash,
      dto.pass,
    );
    if (!pwdmatch) {
      throw new ForbiddenException(
        'Credentials taken',
      );
    }
    delete user.hash;
    return user;
  }
  async signup(dto: AuthDto) {
    const hash = await argon.hash(dto.pass);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash: hash,
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
        },
      });
      return user;
    } catch (e) {
      if (e.code === 'P2021') {
        throw new ForbiddenException(
          'Credentials taken',
        );
      }
      throw e;
    }
  }
}
