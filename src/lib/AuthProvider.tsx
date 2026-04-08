"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  ReactNode,
} from "react";
import { getAuthToken } from "./auth";

const AuthContext = createContext<{ token: string | null; loading: boolean }>({
  token: null,
  loading: true,
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAuthToken()
      .then(setToken)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <AuthContext.Provider value={{ token, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
