import torch
import torch.nn as nn

class Attention(nn.Module):
    def __init__(self, hidden_dim):
        super(Attention, self).__init__()
        self.attn = nn.Linear(hidden_dim * 2, 1)

    def forward(self, lstm_output):
        # lstm_output: [batch, seq_len, hidden_dim * 2]
        attn_weights = torch.softmax(self.attn(lstm_output), dim=1)
        # Context vector
        context = torch.sum(attn_weights * lstm_output, dim=1)
        return context, attn_weights

class BiLSTMIDS(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_layers, num_classes, dropout=0.2):
        super(BiLSTMIDS, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_dim, 
            hidden_dim, 
            num_layers, 
            batch_first=True, 
            bidirectional=True, 
            dropout=dropout if num_layers > 1 else 0
        )
        
        self.attention = Attention(hidden_dim)
        
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_classes)
        )
        
    def forward(self, x):
        h0 = torch.zeros(self.num_layers * 2, x.size(0), self.hidden_dim).to(x.device)
        c0 = torch.zeros(self.num_layers * 2, x.size(0), self.hidden_dim).to(x.device)
        
        # out: [batch, seq_len, hidden_dim * 2]
        out, _ = self.lstm(x, (h0, c0))
        
        # Apply Attention
        context, _ = self.attention(out)
        
        # Decode the context vector
        logits = self.fc(context)
        return logits

