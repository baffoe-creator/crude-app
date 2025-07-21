document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const loginForm = document.getElementById('login');
    const registerForm = document.getElementById('register');
    const showRegister = document.getElementById('show-register');
    const showLogin = document.getElementById('show-login');
    const authSection = document.getElementById('auth-section');
    const userSection = document.getElementById('user-section');
    const usernameDisplay = document.getElementById('username-display');
    const logoutBtn = document.getElementById('logout');
    const tasksContainer = document.getElementById('tasks-container');
    const tasksList = document.getElementById('tasks-list');
    const addTaskBtn = document.getElementById('add-task-btn');
    const taskModal = document.getElementById('task-modal');
    const modalTitle = document.getElementById('modal-title');
    const taskForm = document.getElementById('task-form');
    const closeModal = document.querySelector('.close');
    const deleteTaskBtn = document.getElementById('delete-task');
    const currentAttachmentDiv = document.getElementById('current-attachment');
    const removeAttachmentBtn = document.getElementById('remove-attachment');
    
    // State
    let currentUser = null;
    let tasks = [];
    let currentTaskId = null;
    let currentAttachment = null;

    // Event Listeners
    showRegister.addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('login-form').style.display = 'none';
        document.getElementById('register-form').style.display = 'block';
    });

    showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('register-form').style.display = 'none';
        document.getElementById('login-form').style.display = 'block';
    });

    loginForm.addEventListener('submit', handleLogin);
    registerForm.addEventListener('submit', handleRegister);
    logoutBtn.addEventListener('click', handleLogout);
    addTaskBtn.addEventListener('click', () => openTaskModal());
    closeModal.addEventListener('click', () => taskModal.style.display = 'none');
    taskForm.addEventListener('submit', handleTaskSubmit);
    deleteTaskBtn.addEventListener('click', handleDeleteTask);
    removeAttachmentBtn.addEventListener('click', () => {
        currentAttachment = null;
        document.getElementById('task-attachment').value = '';
        currentAttachmentDiv.style.display = 'none';
    });

    // Close modal when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === taskModal) {
            taskModal.style.display = 'none';
        }
    });

    // Functions
    async function handleLogin(e) {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                currentUser = { username };
                localStorage.setItem('token', data.accessToken);
                updateUI();
                fetchTasks();
            } else {
                alert(data.error || 'Login failed');
            }
        } catch (err) {
            console.error('Login error:', err);
            alert('An error occurred during login');
        }
    }

    async function handleRegister(e) {
        e.preventDefault();
        const username = document.getElementById('register-username').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });

            const data = await response.json();

            if (response.ok) {
                currentUser = { username };
                localStorage.setItem('token', data.accessToken);
                updateUI();
                fetchTasks();
            } else {
                alert(data.error || 'Registration failed');
            }
        } catch (err) {
            console.error('Registration error:', err);
            alert('An error occurred during registration');
        }
    }

    function handleLogout() {
        localStorage.removeItem('token');
        currentUser = null;
        tasks = [];
        updateUI();
    }

    function updateUI() {
        if (currentUser) {
            authSection.style.display = 'none';
            userSection.style.display = 'block';
            tasksContainer.style.display = 'block';
            usernameDisplay.textContent = currentUser.username;
        } else {
            authSection.style.display = 'block';
            document.getElementById('login-form').style.display = 'block';
            document.getElementById('register-form').style.display = 'none';
            userSection.style.display = 'none';
            tasksContainer.style.display = 'none';
            tasksList.innerHTML = '';
        }
    }

    async function fetchTasks() {
        const token = localStorage.getItem('token');
        if (!token) return;

        try {
            const response = await fetch('/api/tasks', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                tasks = await response.json();
                renderTasks();
            } else {
                console.error('Failed to fetch tasks');
            }
        } catch (err) {
            console.error('Error fetching tasks:', err);
        }
    }

    function renderTasks() {
        tasksList.innerHTML = '';
        
        if (tasks.length === 0) {
            tasksList.innerHTML = '<p>No tasks found. Add your first task!</p>';
            return;
        }

        tasks.forEach(task => {
            const taskCard = document.createElement('div');
            taskCard.className = 'task-card';
            
            let attachmentHtml = '';
            if (task.attachment_path) {
                const fileName = task.attachment_path.split('/').pop();
                attachmentHtml = `<p><strong>Attachment:</strong> <a href="/${task.attachment_path}" target="_blank">${fileName}</a></p>`;
            }

            let dueDateHtml = '';
            if (task.due_date) {
                const dueDate = new Date(task.due_date);
                dueDateHtml = `<p><strong>Due:</strong> ${dueDate.toLocaleString()}</p>`;
            }

            taskCard.innerHTML = `
                <h3>${task.title}</h3>
                <span class="task-status ${task.status.replace(' ', '-')}">${task.status}</span>
                <p>${task.description || 'No description'}</p>
                ${dueDateHtml}
                ${attachmentHtml}
                <div class="task-actions">
                    <button class="edit-task" data-id="${task.id}">Edit</button>
                    <button class="delete-task" data-id="${task.id}">Delete</button>
                </div>
            `;

            tasksList.appendChild(taskCard);
        });

        // Add event listeners to action buttons
        document.querySelectorAll('.edit-task').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const taskId = e.target.getAttribute('data-id');
                openTaskModal(taskId);
            });
        });

        document.querySelectorAll('.delete-task').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const taskId = e.target.getAttribute('data-id');
                if (confirm('Are you sure you want to delete this task?')) {
                    deleteTask(taskId);
                }
            });
        });
    }

    function openTaskModal(taskId = null) {
        currentTaskId = taskId;
        currentAttachment = null;
        document.getElementById('task-attachment').value = '';
        currentAttachmentDiv.style.display = 'none';

        if (taskId) {
            // Editing existing task
            modalTitle.textContent = 'Edit Task';
            deleteTaskBtn.style.display = 'block';
            
            const task = tasks.find(t => t.id == taskId);
            if (task) {
                document.getElementById('task-id').value = task.id;
                document.getElementById('task-title').value = task.title;
                document.getElementById('task-description').value = task.description || '';
                document.getElementById('task-status').value = task.status;
                
                if (task.due_date) {
                    const dueDate = new Date(task.due_date);
                    const localDateTime = dueDate.toISOString().slice(0, 16);
                    document.getElementById('task-due-date').value = localDateTime;
                } else {
                    document.getElementById('task-due-date').value = '';
                }

                if (task.attachment_path) {
                    const fileName = task.attachment_path.split('/').pop();
                    document.getElementById('attachment-name').textContent = fileName;
                    currentAttachmentDiv.style.display = 'block';
                    currentAttachment = task.attachment_path;
                }
            }
        } else {
            // Adding new task
            modalTitle.textContent = 'Add New Task';
            deleteTaskBtn.style.display = 'none';
            taskForm.reset();
        }

        taskModal.style.display = 'block';
    }

    async function handleTaskSubmit(e) {
        e.preventDefault();
        
        const token = localStorage.getItem('token');
        if (!token) {
            alert('Please login first');
            return;
        }

        const formData = new FormData();
        const title = document.getElementById('task-title').value;
        const description = document.getElementById('task-description').value;
        const status = document.getElementById('task-status').value;
        const dueDate = document.getElementById('task-due-date').value;
        const attachment = document.getElementById('task-attachment').files[0];

        formData.append('title', title);
        formData.append('description', description);
        formData.append('status', status);
        if (dueDate) formData.append('due_date', dueDate);
        if (attachment) formData.append('attachment', attachment);

        try {
            let response;
            if (currentTaskId) {
                // Update existing task
                response = await fetch(`/api/tasks/${currentTaskId}`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    body: formData
                });
            } else {
                // Create new task
                response = await fetch('/api/tasks', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    body: formData
                });
            }

            if (response.ok) {
                taskModal.style.display = 'none';
                fetchTasks();
            } else {
                const error = await response.json();
                alert(error.error || 'Failed to save task');
            }
        } catch (err) {
            console.error('Error saving task:', err);
            alert('An error occurred while saving the task');
        }
    }

    async function handleDeleteTask() {
        if (!currentTaskId) return;
        
        if (confirm('Are you sure you want to delete this task?')) {
            await deleteTask(currentTaskId);
            taskModal.style.display = 'none';
        }
    }

    async function deleteTask(taskId) {
        const token = localStorage.getItem('token');
        if (!token) return;

        try {
            const response = await fetch(`/api/tasks/${taskId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                fetchTasks();
            } else {
                console.error('Failed to delete task');
            }
        } catch (err) {
            console.error('Error deleting task:', err);
        }
    }

    // Check for existing token on page load
    function checkAuth() {
        const token = localStorage.getItem('token');
        if (token) {
            // Very basic token parsing (in a real app, you'd verify it properly)
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                currentUser = { username: payload.username };
                updateUI();
                fetchTasks();
            } catch (err) {
                console.error('Invalid token:', err);
                localStorage.removeItem('token');
            }
        }
    }

    checkAuth();
});