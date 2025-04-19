import { IsEmail, IsString, MinLength } from 'class-validator'

export class CreateUserDto {
	@IsEmail()
	email: string
}

export class SignInDto {
	@IsEmail()
	email: string

	@IsString()
	@MinLength(8)
	password: string
}

export class VerifyAccountDto {
	@IsString()
	verifyToken: string

	@IsString()
	name: string

	@IsString()
	@MinLength(8)
	newPassword: string
}

export class TerminateSessionDto {
	@IsString()
	toBeTerminated: string
}
