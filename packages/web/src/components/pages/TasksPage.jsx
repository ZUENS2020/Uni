import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { mockTasks } from '../../data/tasks';

const TasksPage = () => {
  const { t } = useTranslation();
  const [tasks, setTasks] = useState(mockTasks);

  const toggleTaskCompletion = (taskId) => {
    setTasks(
      tasks.map((task) =>
        task.id === taskId ? { ...task, completed: !task.completed } : task
      )
    );
  };

  return (
    <div>
      <h2>{t('tasksTitle')}</h2>
      <ul>
        {tasks.map((task) => (
          <li
            key={task.id}
            onClick={() => toggleTaskCompletion(task.id)}
            style={{
              textDecoration: task.completed ? 'line-through' : 'none',
              cursor: 'pointer',
              marginBottom: '0.5rem',
            }}
          >
            <strong>{task.text}</strong>
            <br />
            <small>Deadline: {task.deadline}</small>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default TasksPage;
