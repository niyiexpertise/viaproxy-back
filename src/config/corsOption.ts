import cors from 'cors';
// const allowedOrigins: string[] =
//     [
//         "*",
//     ];

export const corsOptions: cors.CorsOptions = {
  origin: '*',
  preflightContinue: false,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'PUT'],
  credentials: true,
  optionsSuccessStatus: 204,
};
