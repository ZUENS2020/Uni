import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import CalendarPage from './components/pages/CalendarPage';
import TasksPage from './components/pages/TasksPage';
import './App.css';

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<CalendarPage />} />
        <Route path="tasks" element={<TasksPage />} />
      </Route>
    </Routes>
  );
}

export default App;
