import { BadRequestException, ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common'
import { randomBytes } from 'crypto'
import { compare, hash } from 'bcrypt'

import { PrismaService } from '../prisma/prisma.service'
import { EmailService } from 'src/email/email.service'

@Injectable()
export class AuthService {
	private readonly saltRounds = 10;

	constructor(
		private readonly prismaService: PrismaService,
		private readonly emailService: EmailService
	) { }

	async createUserAndSendVerifyEmail(email: string) {
		const candidate = await this.prismaService.user.findUnique({
			where: { email }
		})

		if (candidate) {
			return new ConflictException('User with this email already exists')
		}

		const verifyToken = this.generateVerifyToken()

		await this.prismaService.user.create({
			data: {
				email,
				verifyToken
			}
		})

		this.emailService.sendVerificationEmail(email, verifyToken)

		return {
			message: 'User created successfully'
		}
	}

	async verifyAccountAndCreateSession(
		verifyToken: string,
		name: string,
		newPassword: string,
		deviceName: string
	) {
		const user = await this.prismaService.user.findFirstOrThrow({
			where: {
				verifyToken
			}
		})

		const passwordHash = await this.hashPassword(newPassword)
		
		await this.prismaService.user.update({
			where: { userId: user.userId },
			data: {
				name,
				passwordHash,
				verifyToken: null
			}
		})

		const newSession = await this.prismaService.session.create({
			data: {
				deviceName: deviceName,
				userId: user.userId
			}
		})

		return newSession.sessionId
	}

	async createSession(
		email: string,
		password: string,
		deviceName: string
	) {
		const user = await this.prismaService.user.findUnique({
			where: { email }
		})

		if (!user || !user.passwordHash) {
			throw new BadRequestException('Invalid credentials, try again')
		}

		const isValidPassword = this.comparePassword(password, user.passwordHash)

		if (!isValidPassword) {
			throw new BadRequestException('Invalid credentials, try again')
		}

		const newSession = await this.prismaService.session.create({
			data: {
				deviceName: deviceName,
				userId: user.userId
			}
		})

		return newSession.sessionId
	}

	async terminateSession(
		userSessionId: string,
		toBeTerminated: string
	) {
		const terminatorSession = await this.prismaService.session.findUnique({
			where: {
				sessionId: userSessionId
			}
		})

		if (!terminatorSession) {
			throw new UnauthorizedException('Authorization required')
		}

		const sessionToBeTerminated = await this.prismaService.session.findUnique({
			where: {
				sessionId: toBeTerminated
			}
		})

		if (!sessionToBeTerminated) {
			throw new NotFoundException('Session to be terminated not found')
		}

		if (terminatorSession.userId !== sessionToBeTerminated.userId) {
			throw new UnauthorizedException('User don\'t have access to terminate this session')
		}

		await this.prismaService.session.delete({
			where: {
				sessionId: toBeTerminated
			}
		})
	}

	private async hashPassword(plainPassword: string): Promise<string> {
		const hashedPassword = await hash(plainPassword, this.saltRounds)
		return hashedPassword
	}

	private async comparePassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
		return await compare(plainPassword, hashedPassword)
	}

	private generateVerifyToken(): string {
		return '0x' + randomBytes(20).toString('hex')
	}
}
