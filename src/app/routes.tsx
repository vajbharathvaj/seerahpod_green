import { createBrowserRouter } from "react-router";
import { Layout } from "./components/Layout";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { AudioContent } from "./pages/AudioContent";
import { Playlists } from "./pages/Playlists";
import { Users } from "./pages/Users";
import { Paywall } from "./pages/Paywall";
import { Recommendations } from "./pages/Recommendations";
import { Settings } from "./pages/Settings";

export const router = createBrowserRouter([
  {
    path: "/login",
    Component: Login,
  },
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: Dashboard },
      { path: "audio", Component: AudioContent },
      { path: "playlists", Component: Playlists },
      { path: "users", Component: Users },
      { path: "paywall", Component: Paywall },
      { path: "recommendations", Component: Recommendations },
      { path: "settings", Component: Settings },
    ],
  },
]);
