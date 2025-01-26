import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from 'src/users/users.service';
import { AuthDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
    constructor(
        private userService: UsersService,
        private jwtService: JwtService,
    ) {}

    async login(authDto: AuthDto) {
        const user = await this.userService.findOneByEmail(authDto.email);
        if (!user) {
            throw new BadRequestException(
                'Não foi possível localizar o e-mail em questão.',
            );
        }

        const match = await bcrypt.compare(authDto.password, user.password);
        if (!match) {
            throw new BadRequestException('E-mail ou Senha inválidos.');
        }

        const payload = { sub: user.id, uusername: user.email };

        return {
            access_token: await this.jwtService.signAsync(payload),
        };
    }
}
