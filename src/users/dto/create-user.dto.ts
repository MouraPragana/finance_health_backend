import { IsEmail, IsOptional, IsStrongPassword, IsUUID } from 'class-validator';

export class CreateUserDto {
    @IsOptional()
    @IsUUID()
    id: string;

    @IsEmail()
    email: string;

    @IsStrongPassword({
        minLength: 8,
        minLowercase: 1,
        minNumbers: 1,
        minSymbols: 1,
        minUppercase: 1,
    })
    password: string;
}
