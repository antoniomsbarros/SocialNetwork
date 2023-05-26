import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { resolveConfigFile } from 'prettier';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

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
    return this.signToken(user.id, user.email);
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
  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(
      payload,
      {
        expiresIn: '15m',
        secret: secret,
      },
    );
    return {
      access_token: token,
    };
  }
}
