require('dotenv').config();
const express = require('express');
const multer = require('multer');
const { google } = require('googleapis');
const pdf = require('pdf-parse');
const fs = require('fs');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('./models/User');
const SearchHistory = require('./models/SearchHistory');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
const upload = multer({ dest: 'uploads/' });
app.use(express.json());
app.use(cors());
// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// YouTube API setup
const API_KEY = process.env.YOUTUBE_API_KEY;
const youtube = google.youtube({ version: 'v3', auth: API_KEY });

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// User Registration
app.post('/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user' });
  }
});

// User Login
app.post('/login', [
  body('email').isEmail(),
  body('password').exists(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Upload Endpoint (Authenticated)
app.post('/upload', authenticate, upload.single('syllabus'), async (req, res) => {
  if (!req.file || req.file.mimetype !== 'application/pdf') {
    return res.status(400).json({ message: 'Please upload a valid PDF file.' });
  }

  const filePath = req.file.path;
  const dataBuffer = fs.readFileSync(filePath);
  const language = req.query.language || 'en';

  try {
    const data = await pdf(dataBuffer);
    const text = data.text;

    const topics = extractTopics(text);
    if (!topics.length) {
      return res.status(400).json({ message: 'No topics found in the syllabus.' });
    }

    const videoLinks = await searchYouTubeVideos(topics, language);

    // Save to search history
    const searchEntry = new SearchHistory({
      userId: req.user.id,
      topics,
      videoLinks,
      language,
    });
    await searchEntry.save();

    res.json({ topics, videoLinks });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ message: error.message || 'Error processing the file.' });
  } finally {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
});

// Get Search History
app.get('/history', authenticate, async (req, res) => {
  try {
    const history = await SearchHistory.find({ userId: req.user.id }).sort({ timestamp: -1 });
    res.json(history);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching history' });
  }
});

// Topic Extraction and YouTube Search (unchanged from your code)
function extractTopics(text) {
  const lines = text.split('\n');
  const topics = [];
  const unitRegex = /^UNIT-[IVX]+:/i;
  const headingRegex = /^[A-Z][A-Za-z\s-]+$/;

  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;

    if (unitRegex.test(trimmedLine)) {
      const heading = trimmedLine.split(':')[1]?.trim();
      if (heading) topics.push(heading);
    } else if (headingRegex.test(trimmedLine) && trimmedLine.length > 3) {
      topics.push(trimmedLine);
    }
  }

  return topics.filter((topic, index, self) => self.indexOf(topic) === index);
}

async function searchYouTubeVideos(topics, language) {
  const videoLinks = [];
  const langName = { en: 'English', hi: 'Hindi', es: 'Spanish', te: 'Telugu' }[language] || 'English';
  const langKeywords = {
    en: ['english', 'in english'],
    hi: ['hindi', 'in hindi'],
    es: ['spanish', 'español', 'in spanish'],
    te: ['telugu', 'in telugu'],
  }[language] || ['english'];

  for (const topic of topics) {
    try {
      const query = `${topic} tutorial in ${langName}`;
      const searchResponse = await youtube.search.list({
        part: 'snippet',
        q: query,
        type: 'video',
        order: 'relevance',
        maxResults: 5,
        relevanceLanguage: language,
        videoDuration: 'medium',
        videoEmbeddable: 'true',
      });

      const items = searchResponse.data.items || [];
      if (!items.length) {
        videoLinks.push({ topic, videos: [] });
        continue;
      }

      const videoIds = items.map((item) => item.id.videoId).join(',');
      const videoResponse = await youtube.videos.list({
        part: 'snippet,statistics',
        id: videoIds,
      });

      const videos = videoResponse.data.items.map((video) => {
        const snippet = video.snippet;
        const stats = video.statistics;
        const viewCount = parseInt(stats.viewCount || 0);
        const likeCount = parseInt(stats.likeCount || 0);
        return {
          title: snippet.title,
          link: `https://www.youtube.com/watch?v=${video.id}`,
          viewCount,
          likeCount,
          thumbnail: snippet.thumbnails.default.url,
        };
      });

      videoLinks.push({ topic, videos: videos.slice(0, 2) });
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      console.error(`Error fetching videos for "${topic}":`, error.message);
      videoLinks.push({ topic, videos: [] });
    }
  }

  return videoLinks;
}

// Start Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
app.get('/temp', (req, res) => {
  res.send('Hello World from Express!');
});
module.exports = app;