import userRoute from './userRoute.js';
const routes = [
    {
        path: '/api/v1/users',
        handler: userRoute
    },
];


const setRoute = (app) => {
    routes.forEach(({ path, handler }) => app.use(path, handler));
};
export default setRoute;