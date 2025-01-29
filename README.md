
# **TeamFlow** A Employee Managment System

**Project Purpose** This web application streamlines employee task submissions, HR workflow monitoring, and payments. Admins manage roles, verify employees, and process payments efficiently using Stripe for enhanced productivity and accountability.

## Brief Description

This employee management web application enables seamless task submissions by employees while allowing HR to monitor workflows and request payments for specific employees. Employees can be marked as verified or unverified, and their detailed information can be accessed. <br> <br>

Admins have robust controls, including revoking HR roles, firing employees, and processing payments via Stripe. Additionally, the admin can view detailed profiles for specific employees to ensure informed decision-making. This application enhances workplace efficiency, transparency, and payroll management.

## Features

📋 **Task Submission by Employees:** Employees can submit their tasks, track progress, and keep records updated.<br>  
📊 **HR Workflow Monitoring** HR can monitor employee progress and manage task assignments.<br>  
🔍 **Employee Verification:** HR can verify or unverify employees, ensuring proper status management.<br>  
💰 **Payment Request Management:** HR can send payment requests for employees based on completed tasks.<br>  
 👤 **Employee Profile Management:** Employees and HR can view, update, and manage employee profiles.<br>  
🔑 **Admin Role Assignment:** Admins can assign and revoke HR roles and control employee permissions.<br>  
⚠️ **Error Handling:** A custom 404 error page redirects users to the homepage in case of invalid URLs, ensuring a smooth browsing experience.<br>  
📱 **Responsive Design:** Fully optimized for all screen sizes, delivering an enjoyable browsing experience on both mobile and desktop devices.<br>  
💳 **Employee Payment Processing:** Admins and HR can process payments using the Stripe payment gateway.<br>
🤝 **Real-Time Collaboration:** Employees and HR can collaborate in real-time for task updates and feedback.<br>
🛠️ **Multi-Role Access Control:** Different user roles (Admin, HR, Employee) have distinct access permissions<br>


## Technologys
🔵 HTML for the basic structure. <br>
🔵 CSS and Tailwind CSS for styling and responsiveness. <br>
🔵 React for the frontend framework. <br>
🔵 JavaScript for logic and interactivity. <br>
🔵 Firebase for Authentication. <br>
🔵 MongoDB for Database. <br>
🔵 Stripe for Payment Gateway.<br>
🔵 Many more library use in this web application. <br>

## NPM Packages Usage

💡 *axios:* For making HTTP requests to the backend. <br>
💡 *firebase:* For user authentication and data management. <br>
💡 *lottie-react:* For integrating animations in the UI. <br>
💡 *react:* The core JavaScript library for building the user interface. <br>
💡 *react-dom:* Provides DOM-related functionality for React. <br>
💡 *react-helmet:* For managing changes to the document head, such as titles and meta tags. <br>
💡 *react-icons:* A library of popular icons for use in the UI. <br>
💡 *swiper:* A modern touch slider for creating carousels and slideshows. <br>
💡 *tailwindcss:* A utility-first CSS framework for rapid UI development. <br>
💡 *daisyui:* A UI component library built on top of TailwindCSS for faster development. <br>
💡 *vite:* A build tool and development server for fast development cycles. <br>
💡 *eslint:* A tool for linting JavaScript code to maintain code quality. <br>
💡 *react-router-dom:* For handling routing within the React application. <br>

## React Concepts Used in TeamFlow

**Component-Based Architecture:** The entire project is structured with reusable, modular components such as Navbar, ServiceCard, Footer, etc. This modular approach makes it easy to manage, extend, and maintain the codebase as the project grows.<br>

**Context API for Global State Management:** Context allows you to pass data deeply through the component tree without having to manually pass props at every level. This is helpful for managing global state (like user authentication or user manage).<br>

**Hooks (useState, useEffect, custom hooks):** React hooks allow you to use state and lifecycle methods in functional components, making code more readable and reusable. <br>

**React Router:** React Router allows you to handle navigation within your single-page application. It is a key feature for setting up routes (like /home, /tasks, /admin).<br>

**Error Boundaries:** Error boundaries are used to catch JavaScript errors in the component tree, log those errors, and display a fallback UI.<br>


## Data Management Strategy in TeamFlow

**Fetching Data with Axios** Handling data fetching and API calls properly is crucial. You can use axios or the native fetch API to make requests to the backend (e.g., fetching employee data or task submissions).<br>

**Data Modeling with Mongoose** Organize and validate MongoDB data using schemas.<br>
 
## Installation

Step-by-step instructions to set up the project locally.

```bash
# Clone the repository
https://github.com/Programming-Hero-Web-Course4/b10a12-server-side-rejaul48.git

# Navigate to the project directory
cd your_repository

# Install dependencies
npm install

```

## Admin Credentials:
**Email:** rejaul.admin@gmail.com <br>
**Pass:** AdminPass48 <br>

## Live Demo
[Live demo link](https://team-flow-48.web.app)

## Contact me
**Email**: [rejaulislammr25@gmail.com](mailto:rejaulislammr25@gmail.com)



