import React, { useState, useEffect } from 'react';
import {
  Grid,
  Paper,
  Typography,
  Button,
  Switch,
  FormControlLabel,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  CircularProgress,
  Alert,
  Box,
} from '@mui/material';
import axios from 'axios';
import { PlayArrow, Stop } from '@mui/icons-material';

const paperStyle = {
  p: 3,
  mb: 3
};

const fileInputStyle = {
  display: 'none'
};

const uploadButtonStyle = {
  mt: 2
};

const statusCardStyle = {
  mt: 2
};

const alertStyle = {
  mb: 2
};

function Dashboard() {
  const [status, setStatus] = useState({
    msdt_disabled: false,
    monitoring_active: false,
  });
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [stats, setStats] = useState({
    safe_files: 0,
    unsafe_files: 0,
    attacks_prevented: 0,
    last_detection: null,
    detection_history: []
  });
  const [autoProtection, setAutoProtection] = useState(true);
  const [monitoringActive, setMonitoringActive] = useState(false);

  const fetchStatus = async () => {
    try {
      const response = await axios.get('/api/status');
      setStatus(response.data);
      setAutoProtection(response.data.auto_protection);
      setMonitoringActive(response.data.monitoring_active);
    } catch (err) {
      setError('Failed to fetch status');
    }
  };

  const fetchActivities = async () => {
    try {
      const response = await axios.get('/api/get_activities');
      setActivities(response.data);
    } catch (err) {
      setError('Failed to fetch activities');
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get('/api/stats');
      setStats(response.data);
    } catch (err) {
      setError('Failed to fetch statistics');
    }
  };

  useEffect(() => {
    fetchStatus();
    fetchActivities();
    fetchStats();
    const interval = setInterval(() => {
      fetchStatus();
      fetchActivities();
      fetchStats();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleMsdtToggle = async () => {
    setLoading(true);
    try {
      const endpoint = status.msdt_disabled ? '/api/enable_msdt' : '/api/disable_msdt';
      await axios.post(endpoint);
      await fetchStatus();
    } catch (err) {
      setError('Failed to toggle MSDT status');
    }
    setLoading(false);
  };

  const handleMonitoringToggle = async () => {
    setLoading(true);
    try {
      await axios.post('/api/toggle_monitoring', {
        enable: !status.monitoring_active,
      });
      await fetchStatus();
    } catch (err) {
      setError('Failed to toggle monitoring');
    }
    setLoading(false);
  };

  const handleAutoProtectionToggle = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/toggle_auto_protection', {
        enable: !autoProtection
      });
      if (response.data.success) {
        await fetchStatus();
      } else {
        setError(response.data.error || 'Failed to toggle auto-protection');
      }
    } catch (err) {
      console.error('Auto-protection toggle error:', err);
      setError('Failed to toggle auto-protection: ' + (err.response?.data?.error || err.message));
    }
    setLoading(false);
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    setLoading(true);
    try {
      const response = await axios.post('/api/scan_file', formData);
      setScanResult(response.data);
    } catch (err) {
      setError('Failed to scan file');
    }
    setLoading(false);
  };

  const startMonitoring = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/toggle_monitoring', { enable: true });
      if (response.data.monitoring) {
        setMonitoringActive(true);
        await fetchStatus();
      } else {
        setError('Failed to start monitoring');
      }
    } catch (err) {
      console.error('Start monitoring error:', err);
      setError('Failed to start monitoring: ' + (err.response?.data?.error || err.message));
    }
    setLoading(false);
  };

  const stopMonitoring = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/toggle_monitoring', { enable: false });
      if (response.data.monitoring === false) {
        setMonitoringActive(false);
        await fetchStatus();
      } else {
        setError('Failed to stop monitoring');
      }
    } catch (err) {
      console.error('Stop monitoring error:', err);
      setError('Failed to stop monitoring: ' + (err.response?.data?.error || err.message));
    }
    setLoading(false);
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      {error && (
        <Alert severity="error" sx={alertStyle} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={paperStyle}>
            <Typography variant="h6" gutterBottom>
              MSDT Control
            </Typography>
            <FormControlLabel
              control={
                <Switch
                  checked={status.msdt_disabled}
                  onChange={handleMsdtToggle}
                  disabled={loading}
                />
              }
              label={`MSDT is currently ${status.msdt_disabled ? 'disabled' : 'enabled'}`}
            />
          </Paper>

          <Paper sx={paperStyle}>
            <Typography variant="h6" gutterBottom>
              Real-time Monitoring
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
              <Button
                variant="contained"
                color="primary"
                onClick={startMonitoring}
                disabled={loading || monitoringActive}
                startIcon={<PlayArrow />}
              >
                Start Monitoring
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={stopMonitoring}
                disabled={loading || !monitoringActive}
                startIcon={<Stop />}
              >
                Stop Monitoring
              </Button>
              <Typography
                variant="body2"
                color={monitoringActive ? "success.main" : "text.secondary"}
                sx={{ ml: 2 }}
              >
                {monitoringActive ? "🔍 Monitoring Active" : "⏹️ Monitoring Stopped"}
              </Typography>
            </Box>
            {monitoringActive && (
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                Monitoring folder for new or modified document files
              </Typography>
            )}
          </Paper>

          <Paper sx={paperStyle}>
            <Typography variant="h6" gutterBottom>
              Protection Statistics
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={4}>
                <Card sx={{ bgcolor: 'success.light', color: 'white', p: 2 }}>
                  <Typography variant="h4">{stats.safe_files}</Typography>
                  <Typography>Safe Files</Typography>
                </Card>
              </Grid>
              <Grid item xs={4}>
                <Card sx={{ bgcolor: 'error.light', color: 'white', p: 2 }}>
                  <Typography variant="h4">{stats.unsafe_files}</Typography>
                  <Typography>Malicious Files</Typography>
                </Card>
              </Grid>
              <Grid item xs={4}>
                <Card sx={{ bgcolor: 'primary.light', color: 'white', p: 2 }}>
                  <Typography variant="h4">{stats.attacks_prevented}</Typography>
                  <Typography>Attacks Prevented</Typography>
                </Card>
              </Grid>
            </Grid>
            
            {stats.last_detection && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle1" gutterBottom>
                  Recent Detections
                </Typography>
                <List dense>
                  {stats.detection_history.map((detection, index) => (
                    <ListItem key={index}>
                      <ListItemText
                        primary={`${detection.file} - ${detection.status}`}
                        secondary={detection.timestamp}
                        primaryTypographyProps={{
                          color: detection.status === 'Malicious' ? 'error' : 'success'
                        }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Box>
            )}
          </Paper>

          <Paper sx={paperStyle}>
            <Typography variant="h6" gutterBottom>
              File Scanner
            </Typography>
            <input
              accept="*/*"
              style={fileInputStyle}
              id="file-upload"
              type="file"
              onChange={handleFileUpload}
              disabled={loading}
            />
            <label htmlFor="file-upload">
              <Button
                variant="contained"
                color="primary"
                component="span"
                sx={uploadButtonStyle}
                disabled={loading}
              >
                Upload File for Scanning
              </Button>
            </label>
            {loading && <CircularProgress />}
            {scanResult && (
              <Card sx={statusCardStyle}>
                <CardContent>
                  <Typography variant="h6">Scan Results</Typography>
                  <Typography>File: {scanResult.file}</Typography>
                  <Typography>MD5: {scanResult.md5}</Typography>
                  <Typography 
                    color={
                      scanResult.risk_level === "Critical" ? "error" :
                      scanResult.risk_level === "High" ? "#ff9800" :
                      scanResult.risk_level === "Medium" ? "#ff9800" :
                      "primary"
                    }
                    sx={{ fontWeight: 'bold', mt: 1 }}
                  >
                    Risk Level: {scanResult.risk_level}
                  </Typography>
                  <Typography 
                    color={scanResult.suspicious ? "error" : "primary"}
                    sx={{ mt: 1 }}
                  >
                    Status: {scanResult.suspicious ? "Suspicious" : "Clean"}
                  </Typography>
                  {scanResult.matches && scanResult.matches.length > 0 && (
                    <>
                      <Typography sx={{ mt: 2, color: 'error.main' }}>
                        Suspicious patterns found:
                      </Typography>
                      <List dense>
                        {scanResult.matches.map((match, index) => (
                          <ListItem key={index}>
                            <ListItemText 
                              primary={match}
                              primaryTypographyProps={{
                                color: 'error.main',
                                style: { wordBreak: 'break-all' }
                              }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </>
                  )}
                </CardContent>
              </Card>
            )}
          </Paper>

          <Paper sx={paperStyle}>
            <Typography variant="h6" gutterBottom>
              Protection Settings
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={status.msdt_disabled}
                      onChange={handleMsdtToggle}
                      disabled={loading}
                    />
                  }
                  label={`MSDT is currently ${status.msdt_disabled ? 'disabled' : 'enabled'}`}
                />
              </Grid>
              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={autoProtection}
                      onChange={handleAutoProtectionToggle}
                      disabled={loading}
                    />
                  }
                  label={
                    <Box>
                      <Typography>
                        Automatic Protection {autoProtection ? 'enabled' : 'disabled'}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {autoProtection 
                          ? "MSDT will be automatically disabled when threats are detected" 
                          : "Manual control of MSDT enabled for testing"}
                      </Typography>
                    </Box>
                  }
                />
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={paperStyle}>
            <Typography variant="h6" gutterBottom>
              Suspicious Activities Log
            </Typography>
            <List>
              {activities.map((activity, index) => (
                <ListItem key={index}>
                  <ListItemText
                    primary={`PID: ${activity.pid}`}
                    secondary={
                      <>
                        <Typography component="span" variant="body2">
                          {activity.timestamp}
                        </Typography>
                        <br />
                        <Typography component="span" variant="body2">
                          {activity.cmdline}
                        </Typography>
                      </>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard; 