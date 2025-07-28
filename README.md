# 📋 Task Manager CRUD App

> A **full-stack** task management system built with **Node.js, Express, PostgreSQL, and vanilla JavaScript**. Features secure authentication, file uploads, and robust task organization. Deploy to **Render** with one click! 🚀

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com)

## ✨ Features

- 🔐 **Secure Authentication** - JWT tokens + bcrypt password hashing
- 📝 **Full CRUD Operations** - Create, read, update, delete tasks
- 📎 **File Attachments** - Upload images, PDFs with server-side validation
- 🔍 **Advanced Search & Filtering** - Filter by status, priority, search by keywords
- 🛡️ **Production-Ready Security** - Rate limiting, CORS, input sanitization
- 📱 **Responsive Design** - Clean UI built with vanilla JavaScript

## 🛠️ Tech Stack

**Backend:**
- Node.js + Express.js
- PostgreSQL database
- JWT authentication
- Multer (file uploads)

**Frontend:**
- Vanilla JavaScript, HTML5, CSS3

**Security:**
- Helmet.js, bcrypt, express-rate-limit

**Deployment:**
- Render (one-click deployment)

## 🚀 Quick Start

### Local Development

```bash
# Clone the repository
git clone https://github.com/yourusername/task-manager.git
cd task-manager

# Install dependencies
npm install

# Start the development server
npm run dev
```

### 🌐 Deploy to Render

1. Fork this repository
2. Click the "Deploy to Render" button above
3. Connect your GitHub account
4. Set environment variables (see below)
5. Deploy! 🎉

## ⚙️ Environment Variables

<details>
<summary><strong>Local Development</strong></summary>

```env
ACCESS_TOKEN_SECRET=your_super_secret_jwt_key
DB_HOST=localhost
DB_PORT=5432
DB_NAME=task_manager
DB_USER=postgres
DB_PASSWORD=your_password
NODE_ENV=development
```
</details>

<details>
<summary><strong>Render Production</strong></summary>

```env
ACCESS_TOKEN_SECRET=your_super_secret_jwt_key
INTERNAL_DATABASE_URL=your_render_postgres_connection_string
NODE_ENV=production
FRONTEND_URL=your_render_app_url
```
</details>

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | User registration |
| `POST` | `/api/auth/login` | User authentication |
| `GET` | `/api/tasks` | Fetch user tasks |
| `POST` | `/api/tasks` | Create new task |
| `PUT` | `/api/tasks/:id` | Update task |
| `DELETE` | `/api/tasks/:id` | Delete task |

## 🎯 Perfect For

- Learning full-stack development
- Portfolio projects
- Small team task management
- Foundation for larger project management apps

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License.

---

⭐ **Star this repo** if you found it helpful!
