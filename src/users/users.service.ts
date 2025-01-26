import { BadRequestException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto) {
    const hasAlreadyRegistered = await this.findOneByEmail(createUserDto.email);

    if (hasAlreadyRegistered) {
      throw new BadRequestException(
        'E-mail já cadastrado em nossa plataforma.',
      );
    }

    const saltOrRounds = 10;
    const hash = await bcrypt.hash(createUserDto.password, saltOrRounds);

    const data = {
      email: createUserDto.email,
      password: hash,
    } as CreateUserDto;

    return this.prisma.user.create({
      data,
      omit: {
        password: true,
      },
    });
  }

  async findOneByEmail(email: string) {
    return await this.prisma.user.findFirst({
      where: {
        email,
      },
    });
  }
}
