import { Credentials, Session, UserValidation } from "..";
import { HttpService } from '@chustasoft/cs-common'

export class AuthorizationService {

    private httpService: HttpService;
    private authorizationApiUrl: string;

    
    constructor(authorizationApiUrl: string) {
        this.authorizationApiUrl = authorizationApiUrl;

        this.httpService = new HttpService();
    }


    public async register(credentials: Credentials): Promise<Session> {
        return this.httpService.post<Credentials, Session>(
            `${this.authorizationApiUrl}api/auth/register`, credentials);
    }

    public async login(credentials: Credentials): Promise<Session> {
        return this.httpService.post<Credentials, Session>(
            `${this.authorizationApiUrl}api/auth/login`, credentials);
    }

    public async confirm(userValidation: UserValidation): Promise<Session> {
        return this.httpService.post<UserValidation, Session>(
            `${this.authorizationApiUrl}api/auth/confirm`, userValidation);
    }

}