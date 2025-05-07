import * as React from "react";
import { useState, useEffect } from "react";
import PropTypes from "prop-types";
import {
  Box,
  Typography,
  GlobalStyles,
} from "@mui/material";
import DashboardIcon from "@mui/icons-material/Dashboard";
import PersonIcon from "@mui/icons-material/Person";
import { AppProvider } from "@toolpad/core/AppProvider";
import { DashboardLayout } from "@toolpad/core/DashboardLayout";
import { useDemoRouter } from "@toolpad/core/internal";
import { createTheme, ThemeProvider } from "@mui/material/styles";
import EventIcon from "@mui/icons-material/Event";

import UserManagement from '../components/UserManagement'
import AdminManagement from '../components/AdminManagement'
import EventManagement from '../components/EventManagement'
import DashboardOverview from "../components/DashboardOverview";

// Add Global Styles for font import
const GlobalFontStyles = () => (
  <GlobalStyles
    styles={`
      @font-face {
        font-family: 'Product Sans';
        src: url('/fonts/ProductSans-Regular.woff2') format('woff2'),
             url('/fonts/ProductSans-Regular.woff') format('woff');
        font-weight: normal;
        font-style: normal;
      }
      
      @font-face {
        font-family: 'Product Sans';
        src: url('/fonts/ProductSans-Bold.woff2') format('woff2'),
             url('/fonts/ProductSans-Bold.woff') format('woff');
        font-weight: bold;
        font-style: normal;
      }
      
      * {
        font-family: 'Product Sans', sans-serif !important;
      }
    `}
  />
);

const NAVIGATION = [
  {
    kind: "header",
    title: "Main items",
  },
  {
    segment: "dashboard",
    title: "Dashboard",
    icon: <DashboardIcon sx={{ color: '#C41E3A' }} />,
  },
  {
    segment: "users",
    title: "Users",
    icon: <PersonIcon sx={{ color: '#C41E3A' }} />,
  },
  {
    segment: "admin",
    title: "Admin",
    icon: <PersonIcon sx={{ color: '#C41E3A' }} />,
  },
  {
    segment: "events",
    title: "Events",
    icon: <EventIcon sx={{ color: '#C41E3A' }} />,
  },
  {
    kind: "divider",
  },
];

const demoTheme = createTheme({
  typography: {
    fontFamily: '"Product Sans", sans-serif',
    h1: {
      fontFamily: '"Product Sans", sans-serif',
      fontWeight: 700,
    },
    h2: {
      fontFamily: '"Product Sans", sans-serif',
      fontWeight: 700,
    },
    h3: {
      fontFamily: '"Product Sans", sans-serif',
      fontWeight: 700,
    },
    h4: {
      fontFamily: '"Product Sans", sans-serif',
      fontWeight: 700,
    },
    h5: {
      fontFamily: '"Product Sans", sans-serif',
      fontWeight: 700,
    },
    h6: {
      fontFamily: '"Product Sans", sans-serif',
      fontWeight: 700,
    },
    body1: {
      fontFamily: '"Product Sans", sans-serif',
    },
    body2: {
      fontFamily: '"Product Sans", sans-serif',
    },
    button: {
      fontFamily: '"Product Sans", sans-serif',
      fontWeight: 700,
    },
  },
  palette: {
    background: {
      default: '#F5F5F5',
      paper: '#F5F5F5',
    },
    text: {
      primary: '#C41E3A',
      secondary: '#C41E3A',
    },
    primary: {
      main: '#C41E3A',
    },
  },
  components: {
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#F5F5F5',
          color: '#C41E3A',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: '#F5F5F5',
          color: '#C41E3A',
        },
      },
    },
    MuiListItemText: {
      styleOverrides: {
        primary: {
          color: '#C41E3A',
          fontFamily: '"Product Sans", sans-serif',
        },
      },
    },
    MuiListItemIcon: {
      styleOverrides: {
        root: {
          color: '#C41E3A',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          fontFamily: '"Product Sans", sans-serif',
          fontWeight: 700,
        },
      },
    },
  },
  colorSchemes: { light: true, dark: false },
  breakpoints: {
    values: {
      xs: 0,
      sm: 600,
      md: 600,
      lg: 1200,
      xl: 1536,
    },
  },
});

const makeAuthorizedRequest = async (url, options = {}) => {
  const currentToken = localStorage.getItem("adminToken"); // Read token here
  if (!currentToken) {
    throw new Error("No authentication token found");
  }

  const headers = {
    Authorization: `Bearer ${currentToken}`, // Use currentToken
    "Content-Type": "application/json",
    ...options.headers,
  };

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.statusText}`);
  }

  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return response.json();
  }

  return {};
};

const CustomLogo = () => (
  <Typography
    variant="h6"
    sx={{
      color: '#C41E3A',
      fontWeight: 'bold',
      padding: '1rem',
      fontFamily: '"Product Sans", sans-serif',
    }}
  >
    CAMPUSXPERIENCE
  </Typography>
);

function DemoPageContent({ pathname }) {
  const currentToken = localStorage.getItem("adminToken"); // Read token here for logging
  console.log("Token in dashboard:", currentToken); // Log the current token
  return (
    <Box
      sx={{
        py: 4,
        width: "100%",
        backgroundColor: '#F5F5F5',
      }}
    >
      {pathname === "/dashboard" && <DashboardOverview />}
      {pathname === "/users" && <UserManagement />}
      {pathname === "/admin" && <AdminManagement />}
      {pathname === "/events" && <EventManagement />}
    </Box>
  );
}

DemoPageContent.propTypes = {
  pathname: PropTypes.string.isRequired,
};

export default function AdminDashboard(props) {
  const { window } = props;
  const router = useDemoRouter("/dashboard");
  const demoWindow = window !== undefined ? window() : undefined;

  return (
    <>
      <GlobalFontStyles />
      <AppProvider
        navigation={NAVIGATION}
        branding={{
          logo: <img src="https://scontent.xx.fbcdn.net/v/t1.15752-9/462642609_534404772907134_3634899074146627064_n.png?stp=cp0_dst-png&_nc_cat=103&ccb=1-7&_nc_sid=0024fc&_nc_eui2=AeGMPerBcltGEBb0u5n2KSKTvADRh3C6DpG8ANGHcLoOkXZ3XKLzmaiEdGXzXhykH8sfVCAEVTDCCPsRQ8HnFcr5&_nc_ohc=e_kNMzvvNZ0Q7kNvgExfdJq&_nc_ad=z-m&_nc_cid=0&_nc_zt=23&_nc_ht=scontent.xx&oh=03_Q7cD1QHpfWd0i5CyBOmzKzvYSeTp1njJn0wjoHfLwtrJrUvMYQ&oe=676B9569" />,
          title: 'CAMPUSXPERIENCE',
        }}
      router={router}
      theme={demoTheme}
      window={demoWindow}
      >
        <DashboardLayout>
          <DemoPageContent pathname={router.pathname} />
        </DashboardLayout>
      </AppProvider>
    </>
  );
}