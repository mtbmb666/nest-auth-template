import { Request, Response } from 'express'
import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common'

import { AuthService } from './auth.service'
import { CreateUserDto, SignInDto, TerminateSessionDto, VerifyAccountDto } from './auth.dto'

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('sign-up')
  async signUp(
    @Body() body: CreateUserDto
  ) {
    return await this.authService.createUserAndSendVerifyEmail(body.email)
  }

  @Post('sign-in')
  async signIn(
    @Req() req: Request,
    @Res() res: Response,
    @Body() body: SignInDto,
  ) {
    const userAgent = req.headers['user-agent'] || 'Unknown Device'
    const session = await this.authService.createSession(body.email, body.password, userAgent)

    res.cookie('sessionId', session, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 365 * 24 * 60 * 60 * 1000,
      path: '/',
      sameSite: 'lax'
    })
    return res.json({ message: 'Sign-in successfully!' })
  }

  @Post('verify-account')
  async verifyAccount(
    @Req() req: Request,
    @Res() res: Response,
    @Body() { verifyToken, name, newPassword }: VerifyAccountDto
  ) {
    const userAgent = req.headers['user-agent'] || 'Unknown Device'
    const session = await this.authService.verifyAccountAndCreateSession(verifyToken, name, newPassword, userAgent)

    res.cookie('sessionId', session, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 365 * 24 * 60 * 60 * 1000,
      path: '/',
      sameSite: 'lax'
    })
    return res.json({ message: 'Account verified successfully!' })
  }

  @Post('sign-out')
  async signOut(
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const sessionId = req.cookies?.sessionId

    await this.authService.terminateSession(sessionId, sessionId)

    res.clearCookie('sessionId', {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: process.env.NODE_ENV === 'production'
    })

    return res.status(200).json({ message: 'Signed out successfully' })
  }

  @Post('terminate-session')
  async terminateSession(
    @Req() req: Request,
    @Res() res: Response,
    @Body('toBeTerminated') toBeTerminated: TerminateSessionDto
  ) {
    const sessionId = req.cookies?.sessionId

    await this.authService.terminateSession(sessionId, toBeTerminated.toBeTerminated)

    res.clearCookie('sessionId', {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: process.env.NODE_ENV === 'production'
    })

    return res.status(200).json({ message: 'Signed out successfully' })
  }
}
