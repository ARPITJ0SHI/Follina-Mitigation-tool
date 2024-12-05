import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Box,
} from '@mui/material';
import { Security } from '@mui/icons-material';

function Navigation() {
  return (
    <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
      <Toolbar>
        <IconButton 
          edge="start" 
          color="inherit" 
          sx={{ marginRight: 2 }}
        >
          <Security />
        </IconButton>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          Follina Mitigation Tool
        </Typography>
      </Toolbar>
    </AppBar>
  );
}

export default Navigation; 