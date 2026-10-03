using Impostor.Api.Games;
using Impostor.Api.Innersloth;
using Impostor.Api.Net.Inner.Objects;

namespace Impostor.Api.Net.Messages.Rpcs
{
    public static class Rpc35UpdateSystem
    {
        public static void Serialize(IMessageWriter writer, SystemTypes systemType, IInnerPlayerControl playerControl, byte state)
        {
            writer.Write((byte)systemType);
            writer.Write(playerControl);
            writer.Write(state);
        }

        // Every system writes a single amount byte, except Ventilation which writes three fields.
        public static void Serialize(IMessageWriter writer, SystemTypes systemType, IInnerPlayerControl playerControl, ushort sequenceId, byte state, byte ventId)
        {
            writer.Write((byte)systemType);
            writer.Write(playerControl);

            if (systemType == SystemTypes.Ventilation)
            {
                writer.Write(sequenceId);
                writer.Write(state);
                writer.Write(ventId);
                return;
            }

            writer.Write(state);
        }

        public static void Deserialize(IMessageReader reader, IGame game, out SystemTypes systemType, out IInnerPlayerControl? playerControl, out byte state)
        {
            systemType = (SystemTypes)reader.ReadByte();
            playerControl = reader.ReadNetObject<IInnerPlayerControl>(game);
            state = reader.ReadByte();

            if (systemType == SystemTypes.Sabotage)
            {
                systemType = (SystemTypes)state;
                state = 0x80;
            }
        }

        public static void Deserialize(IMessageReader reader, IGame game, out SystemTypes systemType, out IInnerPlayerControl? playerControl, out ushort sequenceId, out byte state, out byte ventId)
        {
            systemType = (SystemTypes)reader.ReadByte();
            playerControl = reader.ReadNetObject<IInnerPlayerControl>(game);

            sequenceId = 0;
            state = 0;
            ventId = 0;

            if (systemType == SystemTypes.Ventilation)
            {
                sequenceId = reader.ReadUInt16();
                state = reader.ReadByte();
                ventId = reader.ReadByte();
                return;
            }

            state = reader.ReadByte();

            if (systemType == SystemTypes.Sabotage)
            {
                systemType = (SystemTypes)state;
                state = 0x80;
            }
        }
    }
}
