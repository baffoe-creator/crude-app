Task Manager CRUD Application
A full-stack task management system built with Node.js, Express, PostgreSQL, and vanilla JavaScript, featuring secure authentication, file uploads, and robust task organization. Deployable with one click to Render for hassle-free production hosting.

✨ Features
✅ User Authentication

Secure registration & login with JWT tokens

Password hashing with bcrypt

✅ Task Management (CRUD)

Create, read, update, and delete tasks

Track status (To-Do, In Progress, Done) and priority

✅ File Attachments

Upload images, PDFs, and documents (via Multer)

Server-side validation for secure file handling

✅ Advanced Filtering & Search

Filter by status, priority, due date

Search tasks by title & description

✅ Security & Performance

Rate limiting, CORS protection, and Helmet.js for headers

Input sanitization & validation

✅ Responsive UI

Clean, intuitive design with vanilla JavaScript & CSS3

🛠 Tech Stack
Backend

Node.js + Express.js

PostgreSQL (relational database)

JWT (authentication)

Frontend

Vanilla JavaScript, HTML5, CSS3

Deployment

Render (one-click hosting with managed PostgreSQL)

Security & Utilities

Bcrypt (password hashing)

Multer (file uploads)

Helmet, express-rate-limit (security)

🚀 Quick Start
Local Development
Clone repo:

sh
git clone https://github.com/your-repo/task-manager.git  
Install dependencies:

sh
npm install  
Set up PostgreSQL and configure .env (see below)

Start the server:

sh
npm start  
Access at: http://localhost:3000

One-Click Deployment to Render
https://render.com/images/deploy-to-render-button.svg

Click the button above or create a new Web Service on Render

Connect your GitHub repository

Set environment variables (use Production settings below)

Deploy! Render automatically:

Provisions PostgreSQL database

Handles build process

Monitors health via /health endpoint

🔧 Environment Variables
For Local Development
env
ACCESS_TOKEN_SECRET=your_jwt_secret  
DB_HOST=localhost  
DB_PORT=5432  
DB_NAME=task_manager  
DB_USER=postgres  
DB_PASSWORD=your_password  
For Render (Production)
env
ACCESS_TOKEN_SECRET=your_jwt_secret  
INTERNAL_DATABASE_URL=your_render_postgres_url  
NODE_ENV=production  
FRONTEND_URL=your_frontend_url  
📡 API Endpoints
Endpoint	Method	Description
/api/auth/register	POST	User registration
/api/auth/login	POST	User login (JWT token generation)
/api/tasks	GET	Fetch all user tasks
/api/tasks	POST	Create a new task
/api/tasks/:id	PUT	Update a task
/api/tasks/:id	DELETE	Delete a task
🌟 Why This Stack?
Render eliminates DevOps overhead with:

Managed PostgreSQL databases

Automatic scaling

Free tier for small projects

Vanilla JS Frontend keeps dependencies minimal

JWT Auth provides modern security without complexity
