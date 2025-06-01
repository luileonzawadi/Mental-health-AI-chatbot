import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

export default function ChatApp() {
  const [topics, setTopics] = useState([]);
  const [selectedTopic, setSelectedTopic] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');

  useEffect(() => {
    fetchTopics();
  }, []);

  useEffect(() => {
    if (selectedTopic) {
      fetchMessages(selectedTopic);
    }
  }, [selectedTopic]);

  const fetchTopics = async () => {
    try {
      const res = await axios.get('/conversations');
      setTopics(res.data);
    } catch (error) {
      console.error('Error fetching topics', error);
    }
  };

  const fetchMessages = async (topicId) => {
    try {
      const res = await axios.get(`/messages/${topicId}`);
      setMessages(res.data);
    } catch (error) {
      console.error('Error fetching messages', error);
    }
  };

  const sendMessage = async () => {
    if (!input.trim()) return;

    try {
      const res = await axios.post('/chat', {
        message: input,
        conversation_id: selectedTopic,
      });
      setInput('');
      setSelectedTopic(res.data.conversation_id);
      fetchMessages(res.data.conversation_id);
    } catch (error) {
      console.error('Send message failed', error);
    }
  };

  return (
    <div className="grid grid-cols-4 min-h-screen">
      {/* Sidebar */}
      <div className="col-span-1 bg-gray-100 p-4 space-y-2">
        <h2 className="text-xl font-bold mb-4">Conversations</h2>
        {topics.map((topic) => (
          <Card
            key={topic.id}
            className={`cursor-pointer ${selectedTopic === topic.id ? 'bg-blue-100' : ''}`}
            onClick={() => setSelectedTopic(topic.id)}
          >
            <CardContent className="p-3">{topic.title}</CardContent>
          </Card>
        ))}
      </div>

      {/* Chat Area */}
      <div className="col-span-3 flex flex-col">
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.map((msg, index) => (
            <div key={index} className="space-y-1">
              <div className="text-sm text-gray-500">You</div>
              <div className="bg-gray-200 rounded-xl p-3 max-w-lg">{msg.message}</div>
              <div className="text-sm text-blue-500 mt-2">CalmBot</div>
              <div className="bg-blue-100 rounded-xl p-3 max-w-lg">{msg.response}</div>
            </div>
          ))}
        </div>

        <div className="p-4 border-t flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type your message..."
          />
          <Button onClick={sendMessage}>Send</Button>
        </div>
      </div>
    </div>
  );
}
