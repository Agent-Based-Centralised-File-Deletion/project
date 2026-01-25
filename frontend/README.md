# Agent-Based System for Centralized Files Deletion - Admin Interface

This is the Admin Web Interface and Backend Logic for the Agent-Based System for Centralized Files Deletion in Computer Labs.

## Features

- **Modern, Responsive UI**: Beautiful gradient designs, Font Awesome icons, smooth animations, and mobile-friendly interface with enhanced navigation bar
- **Dark Mode**: Toggle between light and dark themes with persistent preference storage
- **Dashboard**: Submit natural language deletion commands and view agent status with real-time statistics
- **File Verification**: Advanced search and filtering, approve/reject with enhanced confirmations
- **Mock Data**: Automatic generation of test data for development
- **Comprehensive Logging**: Detailed logging of all actions with timestamps
- **Error Handling**: Robust error handling with user-friendly notifications
- **Real-time Updates**: Auto-refresh functionality for live data
- **Enhanced UX**: Loading spinners, toast notifications, hover effects, and intuitive navigation

## Project Structure

- `app.py`: Flask application with enhanced API endpoints, logging, and error handling
- `models.py`: SQLAlchemy models with timestamps and audit trails
- `templates/`: Modern Jinja2 templates with Bootstrap 5 and custom styling
- `static/style.css`: Custom CSS with gradients, animations, and responsive design
- `requirements.txt`: Python dependencies including Font Awesome

## Setup

1. Create a virtual environment (recommended):
   ```
   python -m venv venv
   venv\Scripts\activate  # On Windows
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python app.py
   ```

4. Open your browser and go to `http://127.0.0.1:5000/`

The application will generate mock data automatically, so you can test the UI immediately without real networking components.

## UI Highlights

### Dashboard
- **Statistics Cards**: Real-time counts of total agents, online agents, and pending files with **clickable functionality** to view detailed information
- **Command Submission**: Enhanced form with validation and loading states
- **Agent Overview**: Card-based layout with status indicators and last seen timestamps
- **Enhanced Navigation**: Professional navbar with larger fonts, hover effects, glassmorphism design, and theme toggle

### Verification Page
- **Advanced Search**: Real-time filtering by filename or path
- **Enhanced Table**: Sortable columns, hover effects, and status badges
- **Bulk Actions**: Select all/deselect all with visual feedback
- **Action Buttons**: Approve/reject with confirmation dialogs and loading states
- **Responsive Design**: Optimized for desktop and mobile devices

### Design Elements
- **Color Schemes**: Custom gradients for different statuses and actions
- **Animations**: Fade-in effects, hover transformations, and smooth transitions
- **Icons**: Font Awesome icons throughout for better visual hierarchy
- **Typography**: Modern fonts with proper spacing and readability
- **Shadows**: Subtle shadows for depth and modern appearance

## API Endpoints

- `GET /`: Dashboard page with enhanced UI
- `GET /verification`: File verification page with search capabilities
- `POST /submit-instruction`: Submit a deletion instruction (JSON: `{"instruction": "string"}`)
- `GET /clients-status`: Get list of agents with status and last seen
- `GET /files-preview`: Get list of pending files (supports `?search=query`)
- `POST /approve-deletion`: Approve deletion of files (JSON: `{"file_ids": [1,2,3]}`)
- `POST /reject-deletion`: Reject deletion of files (JSON: `{"file_ids": [1,2,3]}`)

## Interactive Features

### Clickable Statistics Cards
The dashboard features three interactive statistics cards that provide detailed information when clicked:

- **Total Agents Card**: Shows a table with all agents including ID, name, status, last seen time, and IP address
- **Online Agents Card**: Shows only agents with "online" status in a detailed table format
- **Pending Files Card**: Displays all pending files with ID, agent ID, file path, status, and creation timestamp

Each card opens a Bootstrap modal with a responsive table containing the relevant data. The modals are styled consistently with the application's design theme.

### Dark Mode Theme
The application includes a comprehensive dark mode theme that can be toggled using the moon/sun icon in the navigation bar:

- **Persistent Theme**: Your theme preference is saved in localStorage and remembered across sessions
- **Complete Coverage**: All UI elements including cards, tables, modals, forms, and navigation adapt to dark mode
- **Smooth Transitions**: Theme switching includes smooth CSS transitions for a polished experience
- **Accessibility**: Dark mode provides better contrast for extended use and reduces eye strain

## Database Schema

### Agents Table
- `id`: Primary key
- `ip`: Agent IP address
- `status`: online/offline
- `last_seen`: Timestamp of last activity

### FileLogs Table
- `id`: Primary key
- `filename`: File name
- `path`: Full file path
- `agent_id`: Foreign key to Agents
- `status`: pending/approved/rejected
- `created_at`: Creation timestamp
- `approved_at`: Approval timestamp (nullable)

## Security Notes

- Uses environment variable for SECRET_KEY (set `SECRET_KEY` in production)
- Input validation on all endpoints
- Database transactions with rollback on errors
- Logging of all critical operations
- CSRF protection ready (Flask-WTF included)

## Development

- Mock data is regenerated on each app restart
- Debug mode enabled by default (disable in production)
- SQLite database stored in `app.db`
- Auto-refresh every 30-60 seconds for live updates
- Responsive design tested on multiple screen sizes

## Browser Support

- Chrome/Edge: Full feature support
- Firefox: Full feature support
- Safari: Full feature support
- Mobile browsers: Responsive design optimized