const React = require('react');
const ReactCookie = require('react-cookie');

export const AuthContext = React.createContext();

export const AuthContextProvider = ({children}) => {
    const [cookies, setCookie, removeCookie] = ReactCookie.useCookies(['authService']);
    
    /*ADD JWT AFTER LOGIN */
    const login = (jwtStorage,timeout) => {
        setCookie('jwt',jwtStorage);
    }

    /*REMOVE JWT FROM STORAGE */
    const logout = () => {
        removeCookie('jwt');
    }

    /*DONT STORE ANYWHERE */
    const getTokenForAuthorization = () => {
        return cookies.jwt;
    }

    return(
        <AuthContext.Provider value={
            {
                login:login,
                logout:logout,
                getTokenForAuthorization:getTokenForAuthorization
            }
        }>
            {children}
        </AuthContext.Provider>
    )
}