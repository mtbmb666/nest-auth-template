import { Module } from '@nestjs/common'
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { PrismaService } from '../prisma/prisma.service'
import { EmailService } from 'src/email/email.service'

@Module({
  controllers: [AuthController],
  providers: [AuthService, PrismaService, EmailService],
})
export class AuthModule { }
