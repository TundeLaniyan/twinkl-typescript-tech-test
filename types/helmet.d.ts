declare module 'helmet' {
    import { RequestHandler } from 'express';

    interface HelmetOptions {
        contentSecurityPolicy?: boolean | object;
        dnsPrefetchControl?: boolean | object;
        expectCt?: boolean | object;
        frameguard?: boolean | object;
        hidePoweredBy?: boolean | object;
        hsts?: boolean | object;
        ieNoOpen?: boolean;
        noSniff?: boolean;
        permittedCrossDomainPolicies?: boolean | object;
        referrerPolicy?: boolean | object;
        xssFilter?: boolean;
    }

    // Helmet middleware function
    function helmet(options?: HelmetOptions): RequestHandler;

    // Export the helmet function as default
    export default helmet;
}
