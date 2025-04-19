import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import * as nodemailer from 'nodemailer'

@Injectable()
export class EmailService {
	private APP_URL: string

	constructor(
		private readonly configService: ConfigService
	) {
		this.APP_URL = this.configService.get<string>('APP_URL') || 'http://localhost:3000'
	}

	async sendVerificationEmail(email: string, verifyToken: string) {
		const transporter = nodemailer.createTransport({
			service: 'gmail',
			auth: {
				user: this.configService.get<string>('EMAIL_USER'),
				pass: this.configService.get<string>('EMAIL_PASSWORD'),
			},
		})

		const mailOptions = {
			from: this.configService.get<string>('EMAIL_USER'),
			to: email,
			subject: 'Welcome to our [App Name]',
			text: `Please click on the following link to verify your email: ${this.APP_URL}/auth/activate?verifytoken=${verifyToken}`,
		}

		await transporter.sendMail(mailOptions)
	}
}
