"""
ShieldNet — Video Pipeline Tests
"""
import pytest
import os
import numpy as np
import cv2
import tempfile
import asyncio
from backend.services.video.processing.pipeline import VideoAnalysisPipeline
from backend.services.video.integration.analyzer_client import InternalAnalyzerClient

@pytest.fixture
def dummy_video():
    """Create a small dummy video for testing."""
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        path = tmp.name
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(path, fourcc, 20.0, (64, 64))
        for i in range(100):
            frame = np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
            out.write(frame)
        out.release()
    yield path
    if os.path.exists(path):
        os.unlink(path)

@pytest.mark.asyncio
async def test_video_pipeline(dummy_video):
    client = InternalAnalyzerClient()
    pipeline = VideoAnalysisPipeline(analyzer=client, max_workers=2)
    
    result = await pipeline.process_video(dummy_video)
    
    assert "confidence" in result
    assert "frame_count" in result
    assert result["frame_count"] > 0
    assert "frame_results" in result
    assert len(result["frame_results"]) == result["frame_count"]
    assert "processing_duration" in result

@pytest.mark.asyncio
async def test_batch_processor():
    from backend.services.video.processing.batch_processor import BatchProcessor
    
    async def mock_analyzer(frames, metadata):
        return [{"confidence": 0.5} for _ in frames]
    
    processor = BatchProcessor(analyzer_fn=mock_analyzer, batch_size=4)
    
    frame = np.zeros((64, 64, 3), dtype=np.uint8)
    
    # Add 3 frames (no processing yet)
    for i in range(3):
        res = await processor.add_and_process(frame, {"idx": i})
        assert res is None
        
    # Add 4th frame (should trigger processing)
    res = await processor.add_and_process(frame, {"idx": 3})
    assert res is not None
    assert len(res) == 4
    
    # Flush remaining (none)
    res = await processor.flush()
    assert len(res) == 0
@pytest.mark.asyncio
async def test_adaptive_extraction(dummy_video):
    from backend.services.video.extractor.frame_extractor import SmartFrameExtractor
    extractor = SmartFrameExtractor(max_frames=10)
    
    frames = list(extractor.extract_intelligent_frames(dummy_video))
    
    # Should have extracted some frames but much less than 100
    assert len(frames) <= 10
    assert "extraction_stats" not in frames # extractor doesn't return stats in yield, but it's logged
    assert "motion_heatmap" in frames[0]

@pytest.mark.asyncio
async def test_temporal_aggregation():
    from backend.services.video.processing.aggregator import VideoResultAggregator
    aggregator = VideoResultAggregator()
    
    # Mock results with an anomaly burst
    results = [
        {"confidence": 0.1, "is_suspicious": False, "priority": 1.0},
        {"confidence": 0.8, "is_suspicious": True, "priority": 1.0},
        {"confidence": 0.9, "is_suspicious": True, "priority": 1.0},
        {"confidence": 0.85, "is_suspicious": True, "priority": 1.0},
        {"confidence": 0.2, "is_suspicious": False, "priority": 1.0},
    ]
    
    final = aggregator.aggregate(results)
    
    assert final["is_suspicious"] == True
    assert final["anomaly_burst_max"] == 3
    assert final["confidence"] > 0.7

@pytest.mark.asyncio
async def test_pipeline_progress_callback(dummy_video):
    client = InternalAnalyzerClient()
    pipeline = VideoAnalysisPipeline(analyzer=client, max_workers=1, batch_size=2)
    
    progress_updates = []
    async def callback(data):
        progress_updates.append(data)
        
    await pipeline.process_video(dummy_video, on_progress=callback)
    
    assert len(progress_updates) > 0
    assert "progress" in progress_updates[0]
