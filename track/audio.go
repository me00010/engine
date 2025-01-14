package track

import (
	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/bluenviron/gortsplib/v4/pkg/format/rtpmpeg4audio"
	"go.uber.org/zap"
	"m7s.live/engine/v4/codec"
	. "m7s.live/engine/v4/common"
	"m7s.live/engine/v4/util"
)

type Audio struct {
	Media
	CodecID    codec.AudioCodecID
	Channels   byte
	SampleSize byte
	AVCCHead   []byte // 音频包在AVCC格式中，AAC会有两个字节，其他的只有一个字节
	codec.AudioSpecificConfig
	AACDecoder rtpmpeg4audio.Decoder
	AACFormat  *format.MPEG4Audio // 仅在 rtsp 转发 rtsp 时使用
}

func (a *Audio) Attach() {
	if err := a.Publisher.GetStream().AddTrack(a).Await(); err != nil {
		a.Error("attach audio track failed", zap.Error(err))
	} else {
		a.Info("audio track attached", zap.Uint32("sample rate", a.SampleRate))
	}
}

func (a *Audio) Detach() {
	a.Publisher.GetStream().RemoveTrack(a)
}

func (a *Audio) GetName() string {
	if a.Name == "" {
		return a.CodecID.String()
	}
	return a.Name
}

func (a *Audio) GetCodec() codec.AudioCodecID {
	return a.CodecID
}

func (av *Audio) WriteADTS(pts uint32, adts util.IBytes) {

}

func (av *Audio) WriteSequenceHead(sh []byte) error {
	av.Media.WriteSequenceHead(sh)
	return nil
}

func (av *Audio) Flush() {
	if av.CodecID == codec.CodecID_AAC && av.Value.ADTS == nil {
		item := av.BytesPool.Get(7)
		av.ToADTS(av.Value.AUList.ByteLength, item.Value)
		av.Value.ADTS = item
	}
	av.Media.Flush()
	if av.CodecID != codec.CodecID_AAC && !av.iframeReceived {
		av.iframeReceived = true
		av.Attach()
	}
}

func (av *Audio) WriteRawBytes(pts uint32, raw util.IBytes) {
	curValue := av.Value
	curValue.BytesIn += raw.Len()
	av.Value.AUList.Push(av.GetFromPool(raw))
	av.generateTimestamp(pts)
	av.Flush()
}

func (av *Audio) WriteAVCC(ts uint32, frame *util.BLL) {
	av.Value.WriteAVCC(ts, frame)
	av.generateTimestamp(ts * 90)
	av.Flush()
}

func (a *Audio) CompleteAVCC(value *AVFrame) {
	value.AVCC.Push(a.BytesPool.GetShell(a.AVCCHead))
	value.AUList.Range(func(v *util.BLL) bool {
		v.Range(func(v util.Buffer) bool {
			value.AVCC.Push(a.BytesPool.GetShell(v))
			return true
		})
		return true
	})
}

func (a *Audio) CompleteRTP(value *AVFrame) {
	a.PacketizeRTP(value.AUList.ToList()...)
}

func (a *Audio) Narrow() {
	// if a.HistoryRing == nil && a.IDRing != nil {
	// 	a.narrow(int(a.Value.Sequence - a.IDRing.Value.Sequence))
	// }
	a.AddIDR()
}
