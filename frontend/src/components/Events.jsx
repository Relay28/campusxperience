import React, { useState, useEffect } from 'react';
import { Container, Paper, Typography, CircularProgress, List, ListItem, ListItemText, Divider, Button, TextField } from '@mui/material';

export default function EventList() {
    const paperStyle = { padding: '20px', margin: '20px auto', maxWidth: 800 };
    const [events, setEvents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [showForm, setShowForm] = useState(false);
    const [newEvent, setNewEvent] = useState({
        title: '',
        description: '',
        startTime: '',
        endTime: '',
        location: '',
        maxCapacity: '',
    });
    const [editEventId, setEditEventId] = useState(null);

    const baseUrl = 'http://localhost:8080/event';

    useEffect(() => {
        const fetchEvents = async () => {
            try {
                const response = await fetch(`${baseUrl}/getAll`);
                if (!response.ok) throw new Error('Failed to fetch events');
                const data = await response.json();
                setEvents(data);
            } catch (err) {
                setError('Error fetching events');
            } finally {
                setLoading(false);
            }
        };

        fetchEvents();
    }, []);

    const handleSaveEvent = async () => {
        try {
            const response = await fetch(`${baseUrl}/save`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newEvent),
            });
            if (!response.ok) throw new Error('Failed to save event');
            const savedEvent = await response.json();
            setEvents([...events, savedEvent]);
            setShowForm(false);
            setNewEvent({ title: '', description: '', startTime: '', endTime: '', location: '', maxCapacity: '' });
        } catch (err) {
            setError('Error saving event');
        }
    };

    const handleUpdateEvent = async (eventId) => {
        try {
            const response = await fetch(`${baseUrl}/update?eventId=${eventId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newEvent),
            });
            if (!response.ok) throw new Error('Failed to update event');
            const updatedEvent = await response.json();
            setEvents(events.map(event => (event.eventId === eventId ? updatedEvent : event)));
            setEditEventId(null);
            setNewEvent({ title: '', description: '', startTime: '', endTime: '', location: '', maxCapacity: '' });
        } catch (err) {
            setError('Error updating event');
        }
    };

    const handleDeleteEvent = async (eventId) => {
        try {
            const response = await fetch(`${baseUrl}/delete/${eventId}`, { method: 'DELETE' });
            if (!response.ok) throw new Error('Failed to delete event');
            setEvents(events.filter(event => event.eventId !== eventId));
        } catch (err) {
            setError('Error deleting event');
        }
    };

    return (
        <Container>
            <Paper elevation={3} style={paperStyle}>
                <Typography variant="h4" align="center" gutterBottom>
                    Events
                </Typography>

                {error && (
                    <Typography color="error" align="center">
                        {error}
                    </Typography>
                )}

                {loading ? (
                    <CircularProgress />
                ) : (
                    <>
                        <Button 
                            variant="contained" 
                            color="primary" 
                            fullWidth 
                            onClick={() => setShowForm(!showForm)}
                            sx={{ mb: 2 }}
                        >
                            {showForm ? 'Cancel' : 'Create New Event'}
                        </Button>

                        {/* Event Creation Form */}
                        {showForm && (
                            <Paper elevation={2} style={{ padding: '10px', marginBottom: '20px' }}>
                                <Typography variant="h6">New Event</Typography>
                                <TextField
                                    label="Title"
                                    fullWidth
                                    variant="outlined"
                                    value={newEvent.title}
                                    onChange={(e) => setNewEvent({ ...newEvent, title: e.target.value })}
                                    sx={{ mt: 1 }}
                                />
                                <TextField
                                    label="Description"
                                    fullWidth
                                    variant="outlined"
                                    value={newEvent.description}
                                    onChange={(e) => setNewEvent({ ...newEvent, description: e.target.value })}
                                    sx={{ mt: 1 }}
                                />
                                <TextField
                                    label="Start Time"
                                    fullWidth
                                    variant="outlined"
                                    type="datetime-local"
                                    value={newEvent.startTime}
                                    onChange={(e) => setNewEvent({ ...newEvent, startTime: e.target.value })}
                                    sx={{ mt: 1 }}
                                />
                                <TextField
                                    label="End Time"
                                    fullWidth
                                    variant="outlined"
                                    type="datetime-local"
                                    value={newEvent.endTime}
                                    onChange={(e) => setNewEvent({ ...newEvent, endTime: e.target.value })}
                                    sx={{ mt: 1 }}
                                />
                                <TextField
                                    label="Location"
                                    fullWidth
                                    variant="outlined"
                                    value={newEvent.location}
                                    onChange={(e) => setNewEvent({ ...newEvent, location: e.target.value })}
                                    sx={{ mt: 1 }}
                                />
                                <TextField
                                    label="Max Capacity"
                                    fullWidth
                                    variant="outlined"
                                    type="number"
                                    value={newEvent.maxCapacity}
                                    onChange={(e) => setNewEvent({ ...newEvent, maxCapacity: e.target.value })}
                                    sx={{ mt: 1, mb: 1 }}
                                />
                                <Button 
                                    variant="contained" 
                                    color="primary" 
                                    onClick={handleSaveEvent}
                                    fullWidth
                                >
                                    Save Event
                                </Button>
                            </Paper>
                        )}

                        <List>
                            {events.map((event) => (
                                <React.Fragment key={event.eventId}>
                                    <ListItem>
                                        {editEventId === event.eventId ? (
                                            <div>
                                                <TextField
                                                    label="Title"
                                                    fullWidth
                                                    variant="outlined"
                                                    value={newEvent.title}
                                                    onChange={(e) => setNewEvent({ ...newEvent, title: e.target.value })}
                                                    sx={{ mt: 1, mb: 1 }}
                                                />
                                                <TextField
                                                    label="Description"
                                                    fullWidth
                                                    variant="outlined"
                                                    value={newEvent.description}
                                                    onChange={(e) => setNewEvent({ ...newEvent, description: e.target.value })}
                                                    sx={{ mb: 1 }}
                                                />
                                                <TextField
                                                    label="Start Time"
                                                    fullWidth
                                                    variant="outlined"
                                                    type="datetime-local"
                                                    value={newEvent.startTime}
                                                    onChange={(e) => setNewEvent({ ...newEvent, startTime: e.target.value })}
                                                    sx={{ mb: 1 }}
                                                />
                                                <TextField
                                                    label="End Time"
                                                    fullWidth
                                                    variant="outlined"
                                                    type="datetime-local"
                                                    value={newEvent.endTime}
                                                    onChange={(e) => setNewEvent({ ...newEvent, endTime: e.target.value })}
                                                    sx={{ mb: 1 }}
                                                />
                                                <TextField
                                                    label="Location"
                                                    fullWidth
                                                    variant="outlined"
                                                    value={newEvent.location}
                                                    onChange={(e) => setNewEvent({ ...newEvent, location: e.target.value })}
                                                    sx={{ mb: 1 }}
                                                />
                                                <TextField
                                                    label="Max Capacity"
                                                    fullWidth
                                                    variant="outlined"
                                                    type="number"
                                                    value={newEvent.maxCapacity}
                                                    onChange={(e) => setNewEvent({ ...newEvent, maxCapacity: e.target.value })}
                                                    sx={{ mb: 1 }}
                                                />
                                                <Button
                                                    variant="contained"
                                                    color="primary"
                                                    onClick={() => handleUpdateEvent(event.eventId)}
                                                    fullWidth
                                                >
                                                    Save Changes
                                                </Button>
                                            </div>
                                        ) : (
                                            <ListItemText
                                                primary={event.title}
                                                secondary={
                                                    <>
                                                        <Typography variant="body2" color="textSecondary">
                                                            {`Description: ${event.description}`}
                                                        </Typography>
                                                        <Typography variant="body2" color="textSecondary">
                                                            {`Start Time: ${new Date(event.startTime).toLocaleString()}`}
                                                        </Typography>
                                                        <Typography variant="body2" color="textSecondary">
                                                            {`End Time: ${new Date(event.endTime).toLocaleString()}`}
                                                        </Typography>
                                                        <Typography variant="body2" color="textSecondary">
                                                            {`Location: ${event.location}`}
                                                        </Typography>
                                                        <Typography variant="body2" color="textSecondary">
                                                            {`Max Capacity: ${event.maxCapacity}`}
                                                        </Typography>
                                                    </>
                                                }
                                            />
                                        )}
                                        <Button
                                            variant="outlined"
                                            color="secondary"
                                            onClick={() => setEditEventId(event.eventId === editEventId ? null : event.eventId)}
                                            sx={{ ml: 1 }}
                                        >
                                            {editEventId === event.eventId ? 'Cancel' : 'Update'}
                                        </Button>
                                        <Button
                                            variant="outlined"
                                            color="error"
                                            onClick={() => handleDeleteEvent(event.eventId)}
                                            sx={{ ml: 1 }}
                                        >
                                            Delete
                                        </Button>
                                    </ListItem>
                                    <Divider component="li" />
                                </React.Fragment>
                            ))}
                        </List>
                    </>
                )}
            </Paper>
        </Container>
    );
}
