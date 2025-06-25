const mongoose = require('mongoose');

const searchHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  topics: [String],
  videoLinks: [{
    topic: String,
    videos: [{
      title: String,
      link: String,
      viewCount: Number,
      likeCount: Number,
      thumbnail: String,
    }],
  }],
  language: String,
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model('SearchHistory', searchHistorySchema);