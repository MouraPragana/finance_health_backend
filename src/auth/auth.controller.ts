import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from 'src/guard/auth.guard';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post()
    async login(@Body() authDto: AuthDto) {
        return await this.authService.login(authDto);
    }

    @UseGuards(AuthGuard)
    @Post('verify-token')
    verifyToken(): boolean {
        return true;
    }
}
